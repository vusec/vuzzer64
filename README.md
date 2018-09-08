VUzzer(64)
===========

About
------
This VUzzer is basically a 64-bit version of the original VUzzer (https://github.com/vusec/vuzzer). We have made several changes to make it work on 64-bit. Main efforts are made by Vivek (githubID: vivek425ster) to lift LibDFT to work on 64-bit. This part is still in testing/development phase (which means taint analysis may have bugs!). Functionality wise, this version of VUzzer is same as the original 32-bit VUzzer (with few bugs fixed!). 

Originally (in turn), this Project depends heavily on a  modified version of DataTracker, which in turn depends on LibDFT pintool. It has some extra tags added in libdft. DataTracker original repo https://github.com/m000/dtracker. The modified code is included with this distribution.

#### Running the VUzzer:
Please see wikiHOWTO.md for a step-by-step procedure to run the VUzzer. This file also contains explanation for most of the options. Also read "datatemp/REDME-dataSet.md" for more information about the datasets and configurations that we used in original VUzzer paper. We have provided seed inputs for several applications in "datatemp" folder.


#Requirements
-------------
The requirements for running VUzzer64 are:

*  A C++11 compiler and unix build utilities (e.g. GNU Make). 
*  Version 2.13 of Intel Pin (yes, we still have this legacy dependency!!). 
*  EWAGBoolArray: https://github.com/lemire/EWAHBoolArray/ - To install it in your system just copy headers file(https://github.com/lemire/EWAHBoolArray/tree/master/headers)
   in /usr/include folder.
*  BitMagic: http://bmagic.sourceforge.net/ - To install it in your system do ```sudo apt-get install bmagic```
*  BitVector module for python.
*  IDA disassembler to run static analysis part of VUzzer. Ashley (a MS student from Grenoble) visited VUSec as intern and developed a 'angr' (http://angr.io/) based static analysis module. The code can be found at https://bitbucket.org/ash09/vuzzer/src/master/. Just check BB-weight-angr.py script. However, it should be noted that we have not tested this script much and one can expect some glitches specially on large complex applications! If you have questions on this script, please direct them to Ashley.

We have tested VUzzer by running it on Ubuntu 14.04 LTS, Linux 3.19.0.80 image. It should be noted that with kernel 4.x.y, Pin (2.13) gets panic. We recommend setting up the same environment to use VUzzer. We repeat kernel 4.x.y does not work. 

#Installation
Follow the steps to install VUzzer64:
```sh
0. cd vuzzer64
1. export PIN_HOME=path_to_pin_directory
2. export PIN_ROOT=path_to_pin_directory
3. export DFT_HOME=$(pwd)/libdft64
4. cd fuzzer-code
5. make -f mymakefile
6. cd ../libdft64
7. make
8. make tools
9. cd ..
```

# Follow wikiHOWTO.md to run VUzzer.


