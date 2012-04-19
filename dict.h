/*
  Dictionary based on code by Morten Eriksen <mortene@sim.no>.
*/

typedef struct dict Dict;

extern Dict *dict_init(unsigned int (*key2hash) (const void *),
		       int (*key_cmp) (const void *, const void *));
extern void dict_clear(Dict *d);
extern int dict_enter(Dict *d, void *key, void *value);
extern void *dict_remove(Dict *d, void *key);
extern void *dict_find_entry(Dict *d, const void *key);
extern void dict_apply_to_all(Dict *d,
			      void (*func) (void *key, void *value, void *data),
			      void *data);

extern unsigned int dict_key2hash_string(const void *key);
extern int dict_key_cmp_string(const void *key1, const void *key2);

extern unsigned int dict_key2hash_int(const void *key);
extern int dict_key_cmp_int(const void *key1, const void *key2);

extern Dict * dict_clone(Dict *old, void * (*key_clone)(void*), void * (*value_clone)(void*));
extern Dict * dict_clone2(Dict * old,
			  void * (* key_clone)(void * key, void * data),
			  void * (* value_clone)(void * value, void * data),
			  void * data);
