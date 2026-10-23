// SWARM bench — toy protector, BELT 1 (white): plain license check, BOOL verdict.
// Build: gcc -O1 -o belt1 belt1.c     Ground truth: check_license() returns 0 for "SWARM-OK-1337".
// Swarm's job: map the check, name the site, demonstrate control. No reading this source.

#include <stdio.h>
#include <string.h>

static int check_license(const char *key) {
    // belt1: single compare. belts 2+ move this behind dispatch, gates, threads, packing, a VM.
    return strcmp(key, "SWARM-OK-1337") == 0;
}

int main(int argc, char **argv) {
    const char *key = argc > 1 ? argv[1] : "";
    if (!check_license(key)) {
        printf("Not valid licence. Exit.\n");
        return 0;
    }
    printf("Licensed. Welcome.\n");
    return 0;
}
