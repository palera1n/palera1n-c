#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <pthread.h>
#include <inttypes.h>
#include <getopt.h>
#include <errno.h>
#include <spawn.h>
#include <sys/mman.h>
#include <time.h>

#include <libusb-1.0/libusb.h>
#include <libimobiledevice/libimobiledevice.h>

#include "ANSI-color-codes.h"
#include "common.h"
#include "checkra1n.h"
#include "kerninfo.h"

unsigned int verbose = 0U;
int enable_rootful = 0, do_pongo_sleep = 0, device_has_booted = 0, demote = 0;
int pongo_thr_running = 0, dfuhelper_thr_running = 0;
bool ohio = true;
char xargs_cmd[0x270] = "xargs wdt=-1";
char checkrain_flags_cmd[0x20] = "checkra1n_flags 0x0";
char palerain_flags_cmd[0x20] = "palera1n_flags 0x0";
char kpf_flags_cmd[0x20] = "kpf_flags 0x0";
char dtpatch_cmd[0x20] = "dtpatch md0";
char rootfs_cmd[512];
extern char** environ;

bool dfuhelper_only = false;
bool pongo_exit = false;
bool palerain_version = false;


niarelap_file_t* kpf_to_upload_1 = &checkra1n_kpf_pongo;
niarelap_file_t* ramdisk_to_upload_1 = &ramdisk_dmg;
niarelap_file_t* overlay_to_upload_1 = &binpack_dmg;

niarelap_file_t** kpf_to_upload = &kpf_to_upload_1;
niarelap_file_t** ramdisk_to_upload = &ramdisk_to_upload_1;
niarelap_file_t** overlay_to_upload = &overlay_to_upload_1;

override_file_t override_ramdisk;
override_file_t override_kpf;
override_file_t override_overlay;

uint32_t checkrain_flags = 0;
uint32_t palerain_flags = 0;
uint32_t kpf_flags = 0;

pthread_t dfuhelper_thread, pongo_thread;
pthread_mutex_t log_mutex;

int build_checks() {
#if defined(__APPLE__)
	struct mach_header_64* c1_header = (struct mach_header_64*)&checkra1n[0];
	if (c1_header->magic != MH_MAGIC_64 && c1_header->magic != MH_CIGAM_64) {
		LOG(LOG_FATAL, "Broken build: checkra1n is not a thin Mach-O");
		return -1;
	}
	if (c1_header->cputype != _mh_execute_header.cputype) {
		LOG(LOG_FATAL, "Broken build: checkra1n CPU type is not the same as %s CPU type", getprogname());
		return -1;
	}
#endif
	struct mach_header_64 *kpf_hdr = (struct mach_header_64 *)checkra1n_kpf_pongo;
	if (kpf_hdr->magic != MH_MAGIC_64 && kpf_hdr->magic != MH_CIGAM_64) {
		LOG(LOG_FATAL, "Broken build: Invalid kernel patchfinder: Not thin 64-bit Mach-O");
		return -1;
	} else if (kpf_hdr->filetype != MH_KEXT_BUNDLE) {
		LOG(LOG_FATAL, "Broken build: Invalid kernel patchfinder: Not a kext bundle");
		return -1;
	} else if (kpf_hdr->cputype != CPU_TYPE_ARM64) {
		LOG(LOG_FATAL, "Broken build: Invalid kernel patchfinder: CPU type is not arm64");
		return -1;
	}
	return 0;
}

void thr_cleanup(void* ptr) {
	*(int*)ptr = 0;
	return;
}

int print_debug_info() {
	fprintf(stderr, "Addresses: \n");
	fprintf(stderr,
		"&verbose = %p\n"
		"&enable_rootful = %p, &do_pongo_sleep = %p, &device_has_booted = %p, &demote = %p\n"
		"&pongo_thr_running = %p, &dfuhelper_thr_running = %p, &ohio = %p\n",
		&verbose,
		&enable_rootful, &do_pongo_sleep, &device_has_booted, &demote,
		&pongo_thr_running, &dfuhelper_thr_running, &ohio
	);
	fflush(stderr);
	return 0;
}

int palera1n(int argc, char *argv[]) {
	int ret = 0;
	int mutex_err = pthread_mutex_init(&log_mutex, NULL);
	if (mutex_err) {
		fprintf(stderr, "palera1n_init: cannot create mutex: %d (%s)\n", errno, strerror(errno));
		return -1;
	}
	if (build_checks()) return -1;
#if defined(__linux__)
	if (access("/proc/self/exe", F_OK) != 0) {
		LOG(LOG_FATAL, "/proc must be mounted");
		return -1;
	}
#endif
	if ((ret = optparse(argc, argv))) goto cleanup;
	if (verbose >= 5) print_debug_info();
	LOG(LOG_INFO, "Waiting for devices");
	do_pongo_sleep = 0;
	pthread_create(&dfuhelper_thread, NULL, dfuhelper, NULL);
	pthread_create(&pongo_thread, NULL, pongo_helper, NULL);
	pthread_join(dfuhelper_thread, NULL);
	if (device_has_booted) goto done;
	if (dfuhelper_only)
		return 0;
	do_pongo_sleep = 1;
	exec_checkra1n();
	if (pongo_exit || demote)
		return 0;
	else
		LOG(LOG_INFO, "Waiting for PongoOS devices...");
#if defined(__APPLE__)
	char buf[PATH_MAX];
	uint32_t bufsize = sizeof(buf);
	_NSGetExecutablePath(buf, &bufsize);
	execv(buf, argv);
#elif defined(__linux__)
	execv("/proc/self/exe", argv);
#else
#error "unsupported"
#endif
	LOG(LOG_FATAL, "exec failed: %d (%s)\n", errno, strerror(errno));
	return -1;
	spin = true;
	// sleep(2);
	// pthread_create(&pongo_thread, NULL, pongo_helper, NULL);
	// pthread_join(pongo_thread, NULL);
    // libusb_exit(NULL);
	while (spin)
	{
		sleep(1);
	}
done:
	if (access("/usr/bin/curl", F_OK) == 0 && ohio) {
		LOG(LOG_VERBOSE4, "Ohio");
		char* ohio_argv[] = {
			"/usr/bin/curl",
			"-sX",
			"POST",
			"-d",
			"{\"app_name\": \"palera1n_c-rewrite\"}",
			"-H",
			"Content-Type: application/json",
			"-H",
			"User-Agent: python-requests/99 palera1n-c-rewrite/0",
			"-o",
			"/dev/null",
			"https://ohio.itsnebula.net/hit",
			NULL
		};
		pid_t pid;
		posix_spawn(&pid, ohio_argv[0], NULL, NULL, ohio_argv, environ);
	}

cleanup:
	if (override_kpf.magic == OVERRIDE_MAGIC) {
		munmap(override_kpf.ptr, (size_t)override_kpf.len);
		close(override_kpf.fd);
	}
	if (override_ramdisk.magic == OVERRIDE_MAGIC) {
		munmap(override_ramdisk.ptr, (size_t)override_ramdisk.len);
		close(override_ramdisk.fd);
	}
	if (override_overlay.magic == OVERRIDE_MAGIC) {
		munmap(override_overlay.ptr, (size_t)override_overlay.len);
		close(override_overlay.fd);
	}
	pthread_mutex_destroy(&log_mutex);
	return ret;
}

int main (int argc, char* argv[]) {
	return palera1n(argc, argv);
}
