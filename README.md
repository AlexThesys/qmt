# Quick Memory Tools  
**Version 0.3.0**  

## ==== Command Line Options ====  

***The program has to be launched in either process or dump inspection mode.***  

`-p` || `--process`	-- launch in process inspection mode  
`-d` || `--dump`	-- launch in dump inspection mode  

`-t=<num_threads>` || `--threads=<num_threads>`	-- limit the number of worker threads  
`-b=<N>` || `--block_info=<N>`	-- alloc block_info size == (dwAllocationGranularity * N), N=[1-8]  
`-f` || `--show-failed-readings`	-- show the regions that failed to be read (process mode only)  
`-h` || `--help`	-- show help (this message)  
`-v` || `--version`	-- show version  

## ==== Common Commands ====  

`?`	- list commands (this message)  
`/ <pattern>`	- search for a hex string  
`/x <pattern>`	- search for a hex value (1-8 bytes wide)  
`/a <pattern>`	- search for an ASCII string  
*All search commands have optional `i|s|h` modifiers to limit the search to image | stack | heap*  

`xb <N> @ <address>`	- hexdump N bytes at address  
`xw <N> @ <address>`	- hexdump N words at address  
`xd <N> @ <address>`	- hexdump N dwords at address  
`xq <N> @ <address>`	- hexdump N qwords at address  
`clear`	- clear screen  
`q | exit`	- quit program  
`lM`	- list process modules  
`lt`	- list process threads  
`lmi`	- list memory regions info  
`lmic`	- list committed memory regions info  

## ==== Process Mode Commands ====  

`p <pid>`	- select PID  
`lp`	- list system PIDs  
`lh`	- traverse process heaps (slow)  
`lhe`	- traverse process heaps, calculate entropy (slower)  
`lhb`	- traverse process heaps, list heap blocks (extra slow)  

## ==== Crash Dump Mode Commands ====  

`/xr <pattern>`	- search for a hex value in GP registers  
`ltr`	- list thread registers  
`lm`	- list memory regions (regions to search through)  
