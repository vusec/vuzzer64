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
#include <ctype.h>

static void
print_symbol_type(FILE *outfile, Symbol *sym)
{
     if (sym->decl) 
	  fprintf(outfile, "%s, <%s %d>",
		  sym->decl,
		  sym->source,
		  sym->def_line);
     else
	  fprintf(outfile, "<>");
}

static int
print_symbol(FILE *outfile, int line, struct output_symbol *s)
{
     print_level(s->level, s->last);
     fprintf(outfile, "%s: ", s->sym->name);
     
     if (brief_listing) {
	  if (s->sym->expand_line) {
	       fprintf(outfile, "%d", s->sym->expand_line);
	       return 1;
	  } else if (s->sym->callee)
	       s->sym->expand_line = line;
     }
     print_symbol_type(outfile, s->sym);
     return 0;
}

int
posix_output_handler(cflow_output_command cmd,
		     FILE *outfile, int line,
		     void *data, void *handler_data)
{
     switch (cmd) {
     case cflow_output_init:
	  /* Additional check for consistency */
	  if (emacs_option)
	       error(EX_USAGE, 0,
		     _("--format=posix is not compatible with --emacs"));
	  brief_listing = print_line_numbers = omit_symbol_names_option = 1;
	  break;
     case cflow_output_begin:
     case cflow_output_end:
     case cflow_output_separator:
	  break;
     case cflow_output_newline:
	  fprintf(outfile, "\n");
	  break;
     case cflow_output_text:
	  fprintf(outfile, "%s", (char*) data);
	  break;
     case cflow_output_symbol:
	  return print_symbol(outfile, line, data);
     }
     return 0;
}
