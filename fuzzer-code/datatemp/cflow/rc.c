/* This file is part of GNU cflow
   Copyright (C) 1997, 2005, 2007, 2010, 2014-2016 Sergey Poznyakoff

   GNU cflow is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   GNU cflow is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#include <cflow.h>
#include <parser.h>
#include <sys/stat.h>
#include <ctype.h>
#include <wordsplit.h>

#ifndef LOCAL_RC
# define LOCAL_RC ".cflowrc"
#endif

static void
expand_argcv(int *argc_ptr, char ***argv_ptr, int argc, char **argv)
{
     int i;
     
     *argv_ptr = xrealloc(*argv_ptr,
			  (*argc_ptr + argc + 1) * sizeof **argv_ptr);
     for (i = 0; i < argc; i++)
	  (*argv_ptr)[*argc_ptr + i] = xstrdup(argv[i]);
     (*argv_ptr)[*argc_ptr + i] = NULL;
     *argc_ptr += argc;
}

/* Parse rc file
 */
void
parse_rc(int *argc_ptr, char ***argv_ptr, char *name)
{
     struct stat st;
     FILE *rcfile;
     int size;
     char *buf, *p;
     struct wordsplit ws;
     int wsflags;
     int line;
     
     if (stat(name, &st))
	  return;
     buf = xmalloc(st.st_size+1);
     rcfile = fopen(name, "r");
     if (!rcfile) {
	  error(EX_FATAL, errno, _("cannot open `%s'"), name);
	  return;
     }
     size = fread(buf, 1, st.st_size, rcfile);
     buf[size] = 0;
     fclose(rcfile);

     ws.ws_comment = "#";
     wsflags = WRDSF_DEFFLAGS | WRDSF_COMMENT;
     line = 0;
     for (p = strtok(buf, "\n"); p; p = strtok(NULL, "\n")) {
	  ++line;
	  if (wordsplit(p, &ws, wsflags))
	       error(EX_FATAL, 0, "%s:%d: %s",
		     name, line, wordsplit_strerror(&ws));
	  wsflags |= WRDSF_REUSE;
	  if (ws.ws_wordc)
	       expand_argcv(argc_ptr, argv_ptr, ws.ws_wordc, ws.ws_wordv);
     }
     if (wsflags & WRDSF_REUSE)
	  wordsplit_free(&ws);
     free(buf);
}

/* Process the value of the environment variable CFLOW_OPTIONS
 * and of the rc file.
 * Split the value into words and add them between (*ARGV_PTR)[0] and
 * (*ARGV_PTR[1]) modifying *ARGC_PTR accordingly.
 * NOTE: Since sourcerc() is not meant to take all SH command line processing
 *       burden, only word splitting is performed and no kind of expansion
 *       takes place. 
 */
void
sourcerc(int *argc_ptr, char ***argv_ptr)
{
     char *env;
     int xargc = 1;
     char **xargv; 

     xargv = xmalloc(2*sizeof *xargv);
     xargv[0] = **argv_ptr;
     xargv[1] = NULL;
     
     env = getenv("CFLOW_OPTIONS");
     if (env) {
	  struct wordsplit ws;

	  ws.ws_comment = "#";
	  if (wordsplit(env, &ws, WRDSF_DEFFLAGS | WRDSF_COMMENT))
	       error(EX_FATAL, 0, "failed to parse CFLOW_OPTIONS: %s",
		     wordsplit_strerror(&ws));
	  if (ws.ws_wordc)
	       expand_argcv(&xargc, &xargv, ws.ws_wordc, ws.ws_wordv);
	  wordsplit_free(&ws);
     }

     env = getenv("CFLOWRC");
     if (env) 
	  parse_rc(&xargc, &xargv, env);
     else {
	  char *home = getenv("HOME");
	  if (home) {
	       int len = strlen(home);
	       char *buf = malloc(len + sizeof(LOCAL_RC)
				  + (home[len-1] != '/') );
	       if (!buf)
		    return;
	       strcpy(buf, home);
	       if (home[len-1] != '/')
		    buf[len++] = '/';
	       strcpy(buf+len, LOCAL_RC);
	       parse_rc(&xargc, &xargv, buf);
	       free(buf);
	  }
     }
     
     if (xargc > 1) {
	  expand_argcv(&xargc, &xargv, *argc_ptr-1, *argv_ptr+1);
	  *argc_ptr = xargc;
	  *argv_ptr = xargv;
     }
}


	
