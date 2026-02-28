import { defineConfig } from 'vite';
import { resolve } from 'node:path';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

export default defineConfig({
    plugins: [
        nodePolyfills({
            include: ['buffer'],
            globals: {
                Buffer: true,
            },
        }),
    ],
    build: {
        rollupOptions: {
            input: {
                main: resolve(__dirname, 'index.html'),
                activity: resolve(__dirname, 'activity.html'),
            },
        },
    },
});
