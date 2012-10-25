#ifndef __MACRO_H_
	#define __MACRO_H_

#define CALC_OFFSET(type, ptr, offset) (type) (((ULONG64) ptr) + offset)
#define CALC_OFFSET_DISP(type, base, offset, disp) (type)((DWORD)(base) + (DWORD)(offset) + disp)
#define CALC_DISP(type, offset, ptr) (type) (((ULONG64) offset) - (ULONG64) ptr)
#endif
