#pragma once
extern char *get_monitor();
extern pcap_t *get_monitorable_device();
extern int activate_monitor(pcap_t *device_handle);
