#ifndef L_MSG_H
#define L_MSG_H

#include "var.h"

struct lua_State;

namespace c2c {

var_t pack2var(const std::string& data);
vec_t pack2vec(const std::string& data);

void var2pack(const var_t& var, std::string& data);
void vec2pack(const vec_t& vec, std::string& data);

void var2lua(const var_t& var, lua_State *L);
int vec2lua(const vec_t& vec, lua_State *L);
var_t lua2var(lua_State *L, int index);
vec_t lua2vec(lua_State *L, int offset, int limit);


var_t json2var(const std::string& data);
void var2json(const var_t& var, std::string& data);
std::string var2json(const var_t& var);

}

#endif
