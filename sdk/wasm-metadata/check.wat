(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"findings\":[{\"id\":\"sdk-wasm-template\",\"title\":\"WASM metadata script executed\",\"severity\":\"info\",\"confidence\":0.9}]}")
  (func (export "alloc") (param $len i32) (result i32)
    (i32.const 4096))
  (func (export "run") (param $input i32) (param $len i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
      (i64.extend_i32_u (i32.const 116))))
)
