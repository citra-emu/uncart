@ this code start at 0x01FF8000 in physical memory on ARM9 and branches to main().

.section .boot


.global Cleanbss
.global svcSleepThread

.type Cleanbss STT_FUNC
.type svcSleepThread STT_FUNC

.align 4
.arm

Cleanbss:
  push {r0-r3}
  ldr r1, =__bss_start
  ldr r2, =__bss_end
  mov r3, #0

  bss_clr:
  cmp r1, r2
  popeq {r0-r3}
  bxeq lr
  str r3, [r1]
  add r1, r1, #4
  b bss_clr
.pool


svcSleepThread:
  svc 0x0A
  bx lr
.pool
