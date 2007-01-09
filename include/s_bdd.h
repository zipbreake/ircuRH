#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

/* s_bdd.h
	Fichero cabecera necesario para trabajar con BDD

  RyDeN - Alberto Alonso - admin@azulverde.net
  09-Febrero-2003 19:10
*/

#define BDD_VERSION 2
#define BDD_START 'a'
#define BDD_END 'z'

#define BDD2_START 'A'
#define BDD2_END   'Z'

#if (BDD2_START > BDD2_END)
#define BDD2_START BDD2_END
#endif

/* Por si acaso... */
#if (BDD_START > BDD_END)
#define BDD_START BDD_END
#endif
#define BDD_TOTAL 256

#define OPER_ALLOWED_X	0x001
#define OPER_ALLOWED_K	0x002
#define OPER_ALLOWED_P	0x004
#define OPER_ALLOWED_H	0x008
#define OPER_ALLOWED_D	0x010
#define OPER_ALLOWED_a	0x020
#define OPER_ALLOWED_A	0x040
#define OPER_ALLOWED_I	0x080
#define OPER_ALLOWED_b	0x100
#define OPER_ALLOWED_B	0x200

#define BDD_BOTS_NICKSERV	"NickServ"
#define BDD_BOTS_VHOSTSERV	"VhostServ"
#define BDD_BOTS_SOCKSCHAN	"SocksChannel"
#define BDD_BOTS_CHANSERV	"ChanServ"

#define BDD_NICKS		'n'
#define BDD_FLAGS		'f'
#define BDD_VHOSTS		'v'
#define BDD_VHOSTS2		'w'
#define BDD_BOTS		'b'
#define BDD_ILINES		'i'
#define BDD_CHANNELS	'C'
#define BDD_BADWORDS	's'
#define BDD_JOINS		'j'

#define BDD_CHANNELS_FOUNDER	"founder"
#define BDD_CHANNELS_MLOCK		"mlock"
#define BDD_CHANNELS_SUCESSOR	"sucessor"

#define MAX_SUBCLAVES		10

struct db_reg {
	char *clave;
	char *valor;
	struct db_reg *next;
};

struct _db2_valores_ {
	char *clave;
	char *valor;
	struct _db2_valores_ *next;
};
struct db2_reg {
	char *clave;
	struct _db2_valores_ *valor;
	struct db2_reg *next;
};

extern unsigned long tabla_registros[BDD_TOTAL][2];
extern unsigned long tabla_hash[BDD_TOTAL][2];

struct db_file__ {
	char *map_p;
	struct stat estado;
	char *read_p;
};
typedef struct db_file__ db_file;

/* Búsqueda */
struct db_reg *db_buscar_registro(char db, char *clave);
struct db2_reg *db2_buscar_registro(char db, char *clave);
struct _db2_valores_ *db2_buscar_en_registro(struct db2_reg *reg, char *subclave);
struct _db2_valores_ *db2_buscar_subclave(char db, char *clave, char *subclave);

/* Iterador */
struct db_reg *db_iterador_init(char tabla);
struct db2_reg *db2_iterador_init(char tabla);
struct db_reg *db_iterador_next(void);
struct db2_reg *db2_iterador_next(void);

/* Buckets */
extern struct db_reg **primer_db[BDD_TOTAL];
extern struct db2_reg **primer_db2[BDD_TOTAL];
