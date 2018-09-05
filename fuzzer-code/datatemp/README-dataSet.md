This file provides few details about the seed that we have provided with the release. Additionally, we also provide information about few  important configuration options that one can use to enhance the VUzzer performance.

* For each applications that we tested with the (original) VUzzer, we have provided seed inputs on the respective folders.
* There are seed inputs for many other applications/formats. 
* We have collected these seed inputs randomely without any further analysis on the properties of these inputs.

# Version of applications used in original VUzzer paper
1. tcptrace version 6.6.7
2. tcpdump version 4.5.1 
3. gif2png 2.5.8
4. mpg321 version 0.3.2
5. pdf2svg 0.2.2

For Libraries:

libpcap: libpcap.so.1.5.3
libjpeg: libjpeg.so.8.0.2
libpoppler: libpoppler.so.44.0.0
linpng: libpng12.so.0.50.0

# A notes on LAVA-M dataset
* While running VUzzer on LAVA-M, in config.py file, we can set 
``` MOSTCOMNLAST= 4 and
RANDOMCOMN= True 
```