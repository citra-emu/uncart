.section ".init"
.global _start
.extern main
.align 4
.arm


_start:
	b _init

	@ required, don't move :)
	@ will be set to FIRM ARM9 entry point by BRAHMA
	arm9ep_backup:  .long 0xFFFF0000


_init:
	stmfd sp!, {r0-r12, lr}
	bl main
	ldmfd sp!, {r0-r12, lr}

	@ return control to FIRM	
	ldr pc, arm9ep_backup
