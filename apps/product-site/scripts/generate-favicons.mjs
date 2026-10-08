import { chromium } from '@playwright/test';
import { readFile, writeFile } from 'node:fs/promises';

const assets = new URL('../public/', import.meta.url);
const svg = await readFile(new URL('favicon.svg', assets), 'utf8');
const browser = await chromium.launch();
try {
  const page = await browser.newPage({ deviceScaleFactor: 1 });
  const images = [];
  for (const size of [16, 32, 48, 96]) {
    await page.setViewportSize({ width: size, height: size });
    await page.setContent(
      `<style>html,body{margin:0}svg{display:block;width:${size}px;height:${size}px}</style>${svg}`,
    );
    const png = await page.screenshot({ type: 'png', omitBackground: true });
    if (size === 96) await writeFile(new URL('favicon.png', assets), png);
    else images.push({ size, png });
  }
  const header = Buffer.alloc(6 + images.length * 16);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(images.length, 4);
  let offset = header.length;
  images.forEach(({ size, png }, index) => {
    const entry = 6 + index * 16;
    header[entry] = size;
    header[entry + 1] = size;
    header.writeUInt16LE(1, entry + 4);
    header.writeUInt16LE(32, entry + 6);
    header.writeUInt32LE(png.length, entry + 8);
    header.writeUInt32LE(offset, entry + 12);
    offset += png.length;
  });
  await writeFile(
    new URL('favicon.ico', assets),
    Buffer.concat([header, ...images.map(({ png }) => png)]),
  );
} finally {
  await browser.close();
}
