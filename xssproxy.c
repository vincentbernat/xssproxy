#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <glib.h>
#include <X11/Xlib.h>
#include <X11/extensions/scrnsaver.h>
#include <dbus/dbus.h>

gboolean verbose = FALSE;
gboolean version = FALSE;
gboolean screensaver_on = FALSE;
Display *display;
GHashTable *apps;

void vmsg(const char *format, ...)
{
    if (!verbose)
        return;
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
    fflush(stdout);
}

void disable_screensaver()
{
    if (!screensaver_on)
        return;
    screensaver_on = FALSE;
    vmsg("Disabling screensaver\n");
    XScreenSaverSuspend(display, 1);
    XFlush(display);
}

void enable_screensaver()
{
    if (screensaver_on)
        return;
    screensaver_on = TRUE;
    vmsg("Enabling screensaver\n");
    XScreenSaverSuspend(display, 0);
    XFlush(display);
}

void handle_exit()
{
    enable_screensaver();
    XCloseDisplay(display);
    vmsg("Terminating\n");
    exit(0);
}

void display_init()
{
    display = XOpenDisplay(NULL);
    if (!display)
    {
        fprintf(stderr, "Could not open display\n");
        exit(1);
    }

    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);

    int event, error, major, minor;
    if (!XScreenSaverQueryExtension(display, &event, &error) ||
        !XScreenSaverQueryVersion(display, &major, &minor) ||
        major < 1 || (major == 1 && minor < 1))
    {
        fprintf(stderr, "XScreenSaverSuspend is not supported\n");
        exit(1);
    }
}

void check_and_exit(DBusError *error)
{
    if (dbus_error_is_set(error))
    {
        fprintf(stderr, "%s", error->message);
        exit(1);
    }
}

void app_disconnect(const char* app)
{
    g_hash_table_remove(apps, app);
    if (g_hash_table_size(apps) == 0)
        enable_screensaver();
}

DBusHandlerResult handle_name_owner_change(DBusConnection *conn, DBusMessage *msg, void *user_data)
{
    if (dbus_message_is_signal(msg,
        "org.freedesktop.DBus", "NameOwnerChanged"))
    {
        const char *name;
        const char *old_owner;
        const char *new_owner;
        DBusError err;
        dbus_error_init(&err);
        dbus_message_get_args(msg, &err,
            DBUS_TYPE_STRING, &name,
            DBUS_TYPE_STRING, &old_owner,
            DBUS_TYPE_STRING, &new_owner,
            DBUS_TYPE_INVALID);
        check_and_exit(&err);
        if (new_owner[0] == '\0')
        {
            vmsg("App disconnect app='%s'\n", name);
            app_disconnect(name);
        }
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

uint32_t inhibit_request(const char *app)
{
    GArray *cookies = g_hash_table_lookup(apps, app);
    if (!cookies)
    {
        disable_screensaver();

        cookies = g_array_new(0, 0, sizeof(uint32_t));
        g_hash_table_insert(apps, g_strdup(app), cookies);
    }
    int i;
    for (i=0; i<cookies->len; i++)
    {
        if (i != g_array_index(cookies, uint32_t, i))
        {
            break;
        }
    }
    g_array_insert_val(cookies, i, i);
    return i;
}

void handle_inhibit(DBusConnection *conn, DBusMessage *msg)
{
    const char *sender = dbus_message_get_sender(msg);
    if (!sender)
        return;
    const char *application_name;
    const char *reason_for_inhibit;
    DBusError err;
    dbus_error_init(&err);
    dbus_message_get_args(msg, &err,
        DBUS_TYPE_STRING, &application_name,
        DBUS_TYPE_STRING, &reason_for_inhibit,
        DBUS_TYPE_INVALID);
    check_and_exit(&err);

    vmsg("Inhibit request app='%s' name='%s' reason='%s'\n",
         sender, application_name, reason_for_inhibit);
    dbus_uint32_t cookie = inhibit_request(sender);

    DBusMessage *reply = dbus_message_new_method_return(msg);
    dbus_message_append_args(reply,
        DBUS_TYPE_UINT32, &cookie,
        DBUS_TYPE_INVALID);
    dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);
}

int compare_func(const void *pkey, const void *pelem)
{
    if (*(uint32_t*)pkey < *(uint32_t*)pelem) return -1;
    if (*(uint32_t*)pkey == *(uint32_t*)pelem) return 0;
    return 1;
}

int find_cookie_index(GArray *cookies, uint32_t cookie)
{
    void *match = bsearch((void*)&cookie, cookies->data, cookies->len, sizeof(uint32_t), compare_func);
    if (!match)
        return -1;
    return ((char*)match - cookies->data) / sizeof(uint32_t);
}

void uninhibit_request(const char *app, uint32_t cookie)
{
    GArray *cookies = g_hash_table_lookup(apps, app);
    if (!cookies)
        return;
    int index = find_cookie_index(cookies, cookie);
    if (index == -1)
        return;
    g_array_remove_index(cookies, index);
    if (cookies->len == 0)
        g_hash_table_remove(apps, app);
    if (g_hash_table_size(apps) == 0)
        enable_screensaver();
}

void handle_uninhibit(DBusConnection *conn, DBusMessage *msg)
{
    const char *sender = dbus_message_get_sender(msg);
    if (!sender)
        return;
    dbus_uint32_t cookie;
    DBusError err;
    dbus_error_init(&err);
    dbus_message_get_args(msg, &err,
        DBUS_TYPE_UINT32, &cookie,
        DBUS_TYPE_INVALID);
    check_and_exit(&err);

    vmsg("Uninhibit request app='%s' cookie='%d'\n", sender, cookie);
    uninhibit_request(sender, cookie);

    DBusMessage *reply = dbus_message_new_method_return(msg);
    dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);
}

DBusHandlerResult handle_method_call(DBusConnection *conn, DBusMessage *msg, void *user_data)
{
    if (dbus_message_is_method_call(msg,
        "org.freedesktop.ScreenSaver", "Inhibit"))
    {
        handle_inhibit(conn, msg);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    if (dbus_message_is_method_call(msg,
        "org.freedesktop.ScreenSaver", "UnInhibit"))
    {
        handle_uninhibit(conn, msg);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

DBusConnection *dbus_conn_init()
{
    DBusError err;
    dbus_error_init(&err);
    DBusConnection *conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
    check_and_exit(&err);
    dbus_bus_request_name(conn, "org.freedesktop.ScreenSaver", 0, &err);
    check_and_exit(&err);

    dbus_bus_add_match(conn,
        "type='signal',sender='org.freedesktop.DBus',path='/org/freedesktop/DBus',"
        "interface='org.freedesktop.DBus',member='NameOwnerChanged'", &err);
    check_and_exit(&err);
    dbus_connection_add_filter(conn, handle_name_owner_change, NULL, NULL);

    DBusObjectPathVTable vtable;
    vtable.message_function = handle_method_call;
    vtable.unregister_function = NULL;

    dbus_connection_try_register_object_path(conn,
        "/ScreenSaver",
        &vtable, NULL, &err);
    check_and_exit(&err);

    return conn;
}

void apps_free_key(gpointer app)
{
    g_free(app);
}

void apps_free_value(gpointer cookies)
{
    g_array_free(cookies, 1);
}

GOptionEntry entries[] =
{
    { "version", 0, 0, G_OPTION_ARG_NONE, &version, "Display version and exit", NULL },
    { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "Be verbose", NULL },
    { NULL },
};

int main(int argc, char *argv[])
{
    GError *error = NULL;
    GOptionContext *context;
    context = g_option_context_new("- forward org.freedesktop.ScreenSaver calls to Xss");
    g_option_context_add_main_entries(context, entries, "xssproxy");
    if (!g_option_context_parse (context, &argc, &argv, &error))
    {
        printf("option parsing failed: %s\n", error->message);
        exit(1);
    }
    if (version)
    {
        printf("xssproxy version 1.0.0\n");
        exit(0);
    }

    display_init();
    DBusConnection *conn = dbus_conn_init();

    apps = g_hash_table_new_full(g_str_hash, g_str_equal,
                                 apps_free_key, apps_free_value);

    while (1)
    {
        dbus_connection_read_write_dispatch(conn, -1);
    }
}
