LUALIB_API int mp_pack(lua_State *L, int offset, int limit, std::string& out);
LUALIB_API int mp_pack(lua_State *L, int offset, int limit, std::vector<char>& out);
LUALIB_API int mp_unpack(lua_State *L);
LUALIB_API int mp_unpack(lua_State *L, const char *s, size_t len);
LUALIB_API int mp_unpack_one(lua_State *L, const char *s, size_t len, int offset);
LUALIB_API int mp_unpack_limit(lua_State *L, const char *s, size_t len, int limit, int offset);

