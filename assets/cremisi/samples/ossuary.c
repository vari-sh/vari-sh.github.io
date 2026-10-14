#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define MAX_NICHES 0x40
#define SEALED     (1u << 3)

/* Each niche of the ossuary keeps one name and one seal. */
typedef enum { BONE, ASH, DUST } relic_kind;

typedef struct {
    char        name[32];
    relic_kind  kind;
    unsigned    flags;
    int         century;
} niche;

static niche ossuary[MAX_NICHES];
static size_t filled = 0;

int inter(const char *name, relic_kind kind, int century) {
    if (filled >= MAX_NICHES || name == NULL) {
        fprintf(stderr, "The ossuary is full\n");
        return -1;
    }
    niche *n = &ossuary[filled++];
    strncpy(n->name, name, sizeof n->name - 1);
    n->kind = kind;
    n->century = century;
    n->flags |= SEALED;
    return (int)filled;
}

int main(void) {
    const char *saints[] = { "Agatha", "Lucia", "Cecilia" };
    for (int i = 0; i < 3; i++) {
        inter(saints[i], i % 2 ? ASH : BONE, 3 + i);
    }
    bool sealed = ossuary[0].flags & SEALED;
    printf("%zu niches, first sealed: %s\t%.1f%%\n",
           filled, sealed ? "true" : "false", 100.0 * filled / MAX_NICHES);
    return 0;
}
