import { nodeResolve } from '@rollup/plugin-node-resolve';
import typescript from "@rollup/plugin-typescript";
import commonjs from '@rollup/plugin-commonjs';
import terser from '@rollup/plugin-terser';
import pkg from './package.json';

export default [
  {
    input: 'src/rsa-message.ts',
    output: [
      { file: pkg.main, format: 'umd', exports: "default", name: "RSAMessage" },
      { file: pkg.common, format: 'cjs', exports: "default", name: "RSAMessage" },
      { file: pkg.module, format: 'es', exports: "default", name: "RSAMessage" }
    ],
    plugins: [
      nodeResolve(),
      typescript(),
      commonjs(),
      //terser()
    ]
  },
]