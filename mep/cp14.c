typedef unsigned int u32;

int _start() {
    *(u32*)0xE3102000 |= 0xf00000;
    *(u32*)0xE3102004 |= 1;
    *(u32*)0xE3101004 |= 1;
    return 0;
}
