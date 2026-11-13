typedef unsigned int u32;

inline void SetMasked(volatile u32* reg, u32 mask, u32 enable) {
    if(enable) *reg |= mask;
    else *reg &= ~mask;
}

inline void ArmGateEnable(u32 mask) {
    SetMasked((u32*)0xE3102000, (mask & 0xf00000) ^ 0x300000, 1);
}

inline void ArmDebuggerGateEnable() {
    SetMasked((u32*)0xE3102004, 1, 1);
}

inline void ArmDebuggerResetDisable() {
    SetMasked((u32*)0xE3101004, 1, 0);
}

int _start() {
    ArmGateEnable(0xc00000);
    ArmDebuggerGateEnable();
    ArmDebuggerResetDisable();
    return 0;
}
