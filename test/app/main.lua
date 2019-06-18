print("Hello App!!!")


local db1 = database("db1")

function db1:func_1(a,b,r)
    print("db1:func_1", a, b)
    if r then
      r({name="db1:func_1",a=a,b=b})
    end
end


db1:func_1(7,8, function(con, t)
    print("REPLY: ",con, t.name, t.a, t.b)
end)

db1:func_1(9,10)
