import { createRequire } from 'module';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import typescript from "@rollup/plugin-typescript";
import commonjs from '@rollup/plugin-commonjs';
import esbuild from 'rollup-plugin-esbuild';

const require = createRequire(import.meta.url);
const pkg = require('./package.json');

export default [
  {
    input: 'src/rsa-message.ts',
    output: [
      { file: pkg.browser, format: 'umd', exports: "default", name: "RSAMessage" },
      { file: pkg.main, format: 'cjs', exports: "default", name: "RSAMessage" },
      { file: pkg.module, format: 'es', exports: "default", name: "RSAMessage" }
    ],
    plugins: [
      nodeResolve(),
      typescript(),
      commonjs(),
      esbuild({ minify: true, target: 'es2015' })
    ]
  },
]