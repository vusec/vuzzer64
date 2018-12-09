/*-
 * Copyright (c) 2010, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in October 2010.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <set>
#include "pin.H"

#include "branch_pred.h"
#include "libdft_api.h"
#include "libdft_core.h"
#include "osutils.H"
#include "syscall_desc.h"
#include "tagmap.h"
#include <assert.h>

KNOB<std::string> KnobImgDesc(KNOB_MODE_WRITEONCE, "pintool", "img_dir", "", "IMG log dir");

static KNOB<std::string> FileKnob(KNOB_MODE_WRITEONCE, "pintool", "filename",
        "osutils.H", "Filename for which we need to track taint"
);

static KNOB<std::string> CmpRawKnob(KNOB_MODE_WRITEONCE, "pintool", "o",
        "cmp.out", "The output file for compare"
);

static KNOB<std::string> LeaRawKnob(KNOB_MODE_WRITEONCE, "pintool", "leao",
        "lea.out", "The output file for lea"
);

static KNOB<std::string> SizeKnob(KNOB_MODE_WRITEONCE, "pintool", "maxoff",
        "4", "Filename for which we need to track taint"
);

static KNOB<std::string> MmapKnob(KNOB_MODE_WRITEONCE, "pintool", "mmap",
        "1", "Method of mmap which we want to spread taint"
);

static KNOB<UINT32> KnobTimeout(KNOB_MODE_WRITEONCE, "pintool", "x",
        "30", "specify timeout in seconds"
);

/* threads context */
extern std::ofstream out;
extern std::ofstream out_lea;
extern thread_ctx_t *threads_ctx;
extern std::string filename;
extern int limit_offset;
extern bool mmap_type;

INT32 Usage()
{
	std::cerr << "This tool demonstrates the use of extended debugger commands" << endl;
	std::cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}
static VOID TimeoutF(VOID *arg){

       sleep(KnobTimeout.Value());
       LOG("Applocation is timout\n");
       PIN_ExitApplication(0);
       PIN_ExitThread(0);
}
int
main(int argc, char **argv, char* envp[])
{
	/* initialize the core tagging engine */
	std::string s;
	if (unlikely(libdft_init(argc, argv) != 0))
		/* failed */
		goto err;

	//f (KnobImgDesc.Value().empty())
	//	return Usage();

	if (FileKnob.Value().empty())
		return Usage();

	mmap_type = 0;
        if (atoi(MmapKnob.Value().c_str())) {
	    mmap_type = 1;
            //read_offset.open("read.out");
        }
	//s = KnobImgDesc.Value() + "/pid";
	//fp = fopen(s.c_str(),"w+");
	//pid = PIN_GetPid();
	//fprintf(fp, "%d\n", pid);
	//fclose(fp);
	KnobImgDesc.Value();
	out.open(CmpRawKnob.Value().c_str(), std::ios::binary | std::ios::trunc | std::ios::out );
	out_lea.open(LeaRawKnob.Value().c_str(), std::ios::binary | std::ios::trunc | std::ios::out );
	filename = FileKnob.Value();
	limit_offset = atoi(SizeKnob.Value().c_str());
    PIN_THREAD_UID threadUid;
    if(KnobTimeout.Value()> 0){
       PIN_SpawnInternalThread(TimeoutF,0,0,&threadUid);
    }

	/* start execution */
	libdft_start();

	/* typically not reached; make the compiler happy */
	return EXIT_SUCCESS;

err:
	/* error handling */

	/* detach from the process */
	libdft_die();

	/* return */
	return EXIT_FAILURE;
}
