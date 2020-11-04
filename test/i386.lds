PHDRS {
	text PT_LOAD FLAGS(5);  /* PF_R | PF_X */
	bss PT_LOAD FLAGS(6);   /* PF_R | PF_W */
}

SECTIONS {
	.text 0x8049000: { *(.text) } :text
	.bss 0x804a000: { *(.bss) *(COMMON) } :bss
	.debug_aranges 0: { *(.debug_aranges) }
	.debug_info 0: { *(.debug_info) }
	.debug_abbrev 0: { *(.debug_abbrev) }
	.debug_line 0: { *(.debug_line) }
	.debug_str 0: { *(.debug_str) }
	/DISCARD/ : { *(*) }
}
