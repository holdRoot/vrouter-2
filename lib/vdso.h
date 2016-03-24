#pragma once

int vdso_init(void);

extern long (*__vdso_getcpu)(unsigned *cpu, unsigned *node, void *unused);

