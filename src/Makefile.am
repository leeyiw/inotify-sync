AUTOMAKE_OPTIONS = gnu

bin_PROGRAMS = inotify-sync

AM_CFLAGS = -DCONF_PATH=\"${sysconfdir}/inotify-sync.conf\"

inotify_sync_SOURCES = inotify-sync.c config.c config.h event_handler.c \
event_handler.h event_watcher.c event_watcher.h utils.c utils.h log.c log.h \
db.c db.h
inotify_sync_LDADD = @LIBOBJS@
