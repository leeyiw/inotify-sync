EXTRA_DIST = actions inotify-sync.conf

inotify_sync_confdir = $(sysconfdir)
inotify_sync_conf_DATA = inotify-sync.conf

inotify_sync_actiondir = $(bindir)/inotify-sync-actions
inotify_sync_sync_actiondir = $(inotify_sync_actiondir)/sync-action
inotify_sync_sync_action_DATA = \
	actions/sync-action/*
inotify_sync_webshell_detectiondir = $(inotify_sync_actiondir)/webshell-detection
inotify_sync_webshell_detection_DATA = \
	actions/webshell-detection/*

inotify_sync_logdir = $(localstatedir)/log/inotify-sync
inotify_sync_log_DATA =

SUBDIRS = src

install-data-hook:
	sed -i -e 's;@inotify_sync_logdir@;$(inotify_sync_logdir);g' \
		-e 's;@inotify_sync_sync_actiondir@;$(inotify_sync_sync_actiondir);g' \
		$(inotify_sync_confdir)/inotify-sync.conf
	chmod a+x $(inotify_sync_webshell_detectiondir)/* $(inotify_sync_sync_actiondir)/*
