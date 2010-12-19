/*
 * Copyright 2009 Edward Nevill
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define DEFAULT_PREFIX	"do_"

static char *prefix = (char *)DEFAULT_PREFIX;

#define ISALPHA(c) (isalpha(c) || (c) == '_')
#define ISALNUM(c) (isalnum(c) || (c) == '_')

FILE *source_f, *bci_f;

typedef struct Bytecode {
	char	*name;
	int	len;
} Bytecode;

typedef struct StringList {
	struct StringList *next;
	char 		*line;
} StringList;

typedef struct OpcodeList {
	struct OpcodeList *next;
	long	 	opcode;
} OpcodeList;

typedef struct OpcodeSequence {
	struct OpcodeSequence *next;
	OpcodeList	*opcode_list;
} OpcodeSequence;

typedef struct BytecodeImpl {
	struct BytecodeImpl *next;
	OpcodeSequence	*opcode_seq;
	StringList	*macro_impl;
	StringList	*direct_impl;
	int		len;
	char		*name;
	char		*do_name;
} BytecodeImpl;

Bytecode bytecodes[256];

BytecodeImpl *the_impl = 0;
BytecodeImpl **the_impl_ptr = &the_impl;

#define BUFLEN 1024

static int lineno = 1;

void fatal(const char *s)
{
	fputs(s, stderr);
	fputc('\n', stderr);
	exit(1);
}

void outmem(void)
{
	fprintf(stderr, "Out of memory\n");
	exit(1);
}

void synerr(void)
{
	fprintf(stderr, "Syntax error at line %d\n", lineno);
	exit(1);
}

int readchar()
{
	int c;

	c = getc(source_f);
	if (c == '\n') lineno++;
	return c;
}

int readwhitespace(int c, char *buf, int len)
{
	int i = 0;

	while ((isspace)(c)) {
		if (buf && i < len-1) buf[i++] = c;
		c = (readchar)();
	}
	if (buf && i < len) buf[i] = 0;
	return c;
}

int skipwhitespace(int c)
{
	while ((isspace)(c)) {
		c = (readchar)();
	}
	return c;
}

int readeol(int c, char *buf, int len)
{
	int i = 0;

	while (c != '\n' && c != EOF) {
		if (buf && i < len-1) buf[i++] = c;
		c = (readchar)();
	}
	if (buf && i < len) buf[i] = 0;
	if (c == '\n') c = (readchar)();
	return c;
}

int skipeol(int c)
{
	while (c != '\n' && c != EOF) c = (readchar)();
	if (c == '\n') c = (readchar)();
	return c;
}

int readsymbol(int c, char *buf, int len)
{
	int i = 0;

	while (ISALNUM(c)) {
		if (buf && i < len-1) buf[i++] = c;
		c = (readchar)();
	}
	if (buf && i < len) buf[i] = 0;
	return c;
}

int bcdef(int c, char *buf, int len)
{
	BytecodeImpl *def;
	OpcodeSequence *seq;
	OpcodeSequence **seqp;
	OpcodeList *opc;
	OpcodeList **opcp;
	StringList *macro, **macrop;
	StringList *direct, **directp;
	char *name;
	char *line;
	int i;
	int length, overall_len;

	def = (BytecodeImpl *)malloc(sizeof(BytecodeImpl));
	if (!def) outmem();
	def->next = 0;
	def->opcode_seq = 0;
	def->macro_impl = 0;
	def->direct_impl = 0;
	def->len = -1;
	*the_impl_ptr = def;
	the_impl_ptr = &(def->next);
	seqp = &(def->opcode_seq);
	overall_len = 0;
	do {
		seq = (OpcodeSequence *)malloc(sizeof(OpcodeSequence));
		if (!seq) outmem();
		seq->next = 0;
		seq->opcode_list = 0;
		*seqp = seq;
		seqp = &(seq->next);
		opcp = &(seq->opcode_list);
		length = -2;
		do {
			c = (readchar)();
			c = skipwhitespace(c);
			if (!ISALPHA(c)) synerr();
			c = readsymbol(c, buf, len);
			c = skipwhitespace(c);
			opc = (OpcodeList *)malloc(sizeof(OpcodeList));
			if (!opc) outmem();
			opc->next = 0;
			opc->opcode = -1;
			*opcp = opc;
			opcp = &(opc->next);
			name = strdup(buf);
			if (!name) outmem();
			for (i = 0; i < 256; i++) {
				if (strcmp(name, bytecodes[i].name) == 0) {
					opc->opcode = i;
					break;
				}
			}
			if (i == 256) {
				fprintf(stderr, "No such opcode '%s'\n", name);
				exit(1);
			}
			if (length == -2) length = bytecodes[i].len;
		} while (c == ',');
		overall_len += length;
		if (c != ')') synerr();
		c = (readchar)();
		c = skipwhitespace(c);
	} while (c == '(');
//	strcpy(buf, "do_");
	*buf = 0;
	if (ISALPHA(c)) {
		c = readsymbol(c, buf, len);
		c = skipwhitespace(c);
	} else {
		seq = def->opcode_seq;
//		strcat(buf, "bytecode");
		while (seq) {
			opc = seq->opcode_list;
			if (*buf) strcat(buf, "_");
			strcat(buf, bytecodes[opc->opcode].name);
//			sprintf(buf+strlen(buf), "_%ld", opc->opcode);
			seq = seq->next;
		}
	}
	name = strdup(buf);
	if (!name) outmem();
	def->name = name;
	def->do_name = name;
	def->len = overall_len;
	if (c != '{') synerr();
	c = (readchar)();
	while (c != '\n' && isspace(c)) c = (readchar)();
	if (c != '\n') synerr();
	c = (readchar)();
	c = readwhitespace(c, buf, len);
	macrop = &(def->macro_impl);
	while (c != '}' && c != EOF) {
		c = readeol(c, buf + strlen(buf), len - strlen(buf));
		line = strdup(buf);
		if (!line) outmem();
		macro = (StringList *)malloc(sizeof(StringList));
		if (!macro) outmem();
		*macrop = macro;
		macrop = &(macro->next);
		macro->next = 0;
		macro->line = line;
		c = readwhitespace(c, buf, len);
	}
	if (c != '}') synerr();
	c = (readchar)();
	c = skipwhitespace(c);
	if (ISALPHA(c)) {
		c = readsymbol(c, buf, len);
		c = skipwhitespace(c);
		name = strdup(buf);
		if (!name) outmem();
		def->do_name = name;
	}
	if (c == '[') {
		c = (readchar)();
		while (c != '\n' && isspace(c)) c = (readchar)();
		if (c != '\n') synerr();
		c = (readchar)();
		c = readwhitespace(c, buf, len);
		directp = &(def->direct_impl);
		while (c != ']' && c != EOF) {
			c = readeol(c, buf + strlen(buf), len - strlen(buf));
			line = strdup(buf);
			if (!line) outmem();
			direct = (StringList *)malloc(sizeof(StringList));
			if (!direct) outmem();
			*directp = direct;
			directp = &(direct->next);
			direct->next = 0;
			direct->line = line;
			c = readwhitespace(c, buf, len);
		}
		if (c != ']') synerr();
		c = (readchar)();
	}
	return c;
}

void mkbc(void)
{
	char buf[BUFLEN];
	char *endptr;
	int c;
	char *name;
	long opcode, len;

	c = (readchar)();
	c = skipwhitespace(c);
	while (c != EOF) {
		if (c == '@' || c == '#') {
			c = skipeol(c);
		} else if (ISALPHA(c)) {
			c = readsymbol(c, buf, BUFLEN);
			c = skipwhitespace(c);
			if (c == '=') {
				name = strdup(buf);
				if (!name) outmem();
				c = (readchar)();
				c = skipwhitespace(c);
				if (!(isdigit)(c)) synerr();
				c = readsymbol(c, buf, BUFLEN);
				opcode = strtol(buf, &endptr, 0);
				if (*endptr != 0) synerr();
				c = skipwhitespace(c);
				if (c != ',') synerr();
				c = (readchar)();
				c = skipwhitespace(c);
				if (!(isdigit)(c)) synerr();
				c = readsymbol(c, buf, BUFLEN);
				len = strtol(buf, &endptr, 0);
				if (*endptr != 0) synerr();
				bytecodes[opcode].name = name;
				bytecodes[opcode].len = len;
			}
		} else if (c == '(') {
			c = bcdef(c, buf, BUFLEN);
		} else synerr();
		c = skipwhitespace(c);
	}
}

typedef struct TableEntry {
	BytecodeImpl *impl;
	char *impl_name;
	char *def_name;
	struct TableEntry *subtable;
} TableEntry;

TableEntry *the_table;

int is_duplicate(TableEntry *a, TableEntry *b)
{
	int i;
	char buf[256];

	for (i = 0; i < 256; i++) {
		if (a[i].subtable || b[i].subtable) {
			if (!(a[i].subtable) || !(b[i].subtable)) return 0;
			if (!is_duplicate(a[i].subtable, b[i].subtable)) return 0;
		} else if (a[i].impl_name && b[i].impl_name) {
			if (strcmp(a[i].impl_name, b[i].impl_name) != 0)
				return 0;
		} else if (a[i].def_name && b[i].def_name) {
			if (strcmp(a[i].def_name, b[i].def_name) != 0)
				return 0;
		} else return 0;
	}
	return 1;
}

void remove_duplicates(TableEntry *table, int start, int *table_indices, int depth)
{
	TableEntry *start_entry = table[start].subtable;
	int i, j;

	if (!start_entry) fatal("Subtable is NULL in remove_duplicates!!!");
	for (i = start+1; i < 256; i++) {
		if (table[i].subtable) {
			if (is_duplicate(start_entry, table[i].subtable)) {
				fputs("dispatch", bci_f);
				for (j = 0; j < depth; j++) {
					fputc('_', bci_f);
					fputs(bytecodes[table_indices[j]].name, bci_f);
				}
				fputc('_', bci_f);
				fputs(bytecodes[i].name, bci_f);
				fputs(":\n", bci_f);
				free(table[i].subtable);
				table[i].subtable = 0;
			}
		}
	}
}

void writeouttable(TableEntry *table, int *table_indices, int depth)
{
	int i, j;
	int len;

	for (i = 0; i < 256; i++) {
		if (table[i].subtable) {
			len = 0;
			fputs("\t.word\tdispatch", bci_f);
			table_indices[depth] = i;
			for (j = 0; j <= depth; j++) {
				fputc('_', bci_f);
				fputs(bytecodes[table_indices[j]].name, bci_f);
				len += bytecodes[table_indices[j]].len;
			}
			fprintf(bci_f, "+%d\n", len);
		} else {
			if (table[i].impl_name)
				fprintf(bci_f, "\t.word\t%s%s\n", prefix, table[i].impl_name);
			else
				fprintf(bci_f, "\t.word\t%s%s\n", prefix, table[i].def_name);
		}
	}
	if (depth == 0) {
		fputs("\t.endm\n", bci_f);
		fputs("\t.macro\tSUB_DISPATCH_TABLES\n", bci_f);
	}
	for (i = 0; i < 256; i++) {
		if (table[i].subtable) {
			fputs("dispatch", bci_f);
			table_indices[depth] = i;
			for (j = 0; j <= depth; j++) {
				fputc('_', bci_f);
				fputs(bytecodes[table_indices[j]].name, bci_f);
			}
			fputs(":\n", bci_f);
			remove_duplicates(table, i, table_indices, depth);
			writeouttable(table[i].subtable, table_indices, depth+1);
		}
	}
}

void do_tableentry(BytecodeImpl *impl, TableEntry **tablep, int *table_indices, int depth)
{
	TableEntry *table;
	char *def = (char *)"undefined";
	int i,j;

	if (depth == 0) fatal("Depth = 0 for tableentry\n");
	for (i = 0; i < depth; i++) {
		table = *tablep;
		if (!table) {
			table = (TableEntry *)malloc(sizeof(TableEntry) * 256);
			if (!table) outmem();
			*tablep = table;
			def = strdup(def);
			if (!def) outmem();
			for (j = 0; j < 256; j++) {
				table[j].impl_name = 0;
				table[j].def_name = def;
				table[j].subtable = 0;
			}
		}
		table = &table[table_indices[i]];
		tablep = &(table->subtable);
		if (table->impl_name) def = table->def_name;
	}
	if (!table->impl_name)
		table->impl_name = impl->do_name;
	table->def_name = impl->do_name;
}

void dumpseq(BytecodeImpl *impl, OpcodeSequence *seq, int *table_indices, int depth)
{
	OpcodeList *opc;

	opc = seq->opcode_list;
	while (opc) {
		table_indices[depth++] = opc->opcode;
		if (seq->next != NULL) {
			dumpseq(impl, seq->next, table_indices, depth);
		} else {
			do_tableentry(impl, &the_table, table_indices, depth);
		}
		depth--;
		opc = opc->next;
	}
}

void dumptable(void)
{
	BytecodeImpl *impl = the_impl;
	int table_indices[256];
	int j;
	char	buf[256];
	char *def;

	the_table = (TableEntry *)malloc(sizeof(TableEntry) * 256);
	if (!the_table) outmem();
	for (j = 0; j < 256; j++) {
		sprintf(buf, "%s", bytecodes[j].name);
		def = strdup(buf);
		if (!def) outmem();
		the_table[j].impl_name = 0;
		the_table[j].def_name = def;
		the_table[j].subtable = 0;
	}
	while (impl) {
		dumpseq(impl, impl->opcode_seq, table_indices, 0);
		impl = impl->next;
	}
	fputs("\t.macro\tMAIN_DISPATCH_TABLE\n", bci_f);
	writeouttable(the_table, table_indices, 0);
	fputs("\t.endm\n", bci_f);
}

void dumpimpl(void)
{
	BytecodeImpl *impl = the_impl;
	OpcodeList *opc;
	StringList *code;
	StringList *sl;
	char buf[BUFLEN];
	char macro[BUFLEN];

	while (impl) {
		buf[0] = 0;
		fprintf(bci_f, "@-----------------------------------------------------------------------------\n");
		fprintf(bci_f, "\t.macro\t%s\tjpc_off=0, seq_len=%d\n", impl->name, impl->len);
		sl = impl->macro_impl;
		while (sl) {
			fputs(sl->line, bci_f);
			fputc('\n', bci_f);
			sl = sl->next;
		}
		fprintf(bci_f, "\t.endm\n\n");
		sl = impl->direct_impl;
		if (sl) {
			do {
				fputs(sl->line, bci_f);
				fputc('\n', bci_f);
				sl = sl->next;
			} while (sl);
		} else {
			fprintf(bci_f, "\tOpcode\t%s\n", impl->do_name);
//			fprintf(bci_f, "%s:\n", impl->do_name);
			fprintf(bci_f, "\t%s\n", impl->name);
//			fprintf(bci_f, "\tDISPATCH\t%d\n", impl->len);
		}
		impl = impl->next;
	}
}

void dumpbc()
{
	int i;

	for (i = 0; i < 256; i++) {
		if (strcmp(bytecodes[i].name, "undefined") != 0)
			fprintf(bci_f, "#define opc_%s\t\t0x%02x\n", bytecodes[i].name, i);
	}
	fputc('\n', bci_f);
	dumpimpl();
	dumptable();
}

void usage(void)
{
	fatal("Usage: mkbc <bytecode definition file> <asm output file>");
}

int main(int argc, char **argv)
{
	int i;
	char *source, *bci;
	char *s;

	source = bci = 0;
	while (s = *++argv) {
		if (s[0] == '-' && s[1] != 0) {
			if (s[1] == 'P') {
				prefix = s+2;
			} else {
				fprintf(stderr, "Unrecognized option %s\n", s);
				usage();
			}
		} else {
			if (!source) source = s;
			else if (!bci) bci = s;
			else {
				fprintf(stderr, "Too many arguments\n");
				usage();
			}
		}
	}
	if (!bci) {
		fprintf(stderr, "Too few arguments\n");
		usage();
	}
	if (strcmp(source, "-") == 0) {
		source_f = stdin;
	} else {
		source_f = fopen(source, "r");
		if (!source_f) fatal("Error opening source file");
	}
	if (strcmp(bci, "-") == 0) {
		bci_f = stdout;
	} else {
		bci_f = fopen(bci, "w");
		if (!bci_f) fatal("Error opening bci file for write");
	}
	for (i = 0; i < 256; i++) {
		bytecodes[i].name = (char *)"undefined";
		bytecodes[i].len = -1;
	}
	mkbc();
	dumpbc();
	if (ferror(source_f)) fatal("Error reading source");
	if (ferror(bci_f)) fatal("Error writing bci");
	if (source_f != stdin) fclose(source_f);
	if (bci_f != stdout) fclose(bci_f);

	return 0;
}
