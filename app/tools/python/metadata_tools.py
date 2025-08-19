#!/usr/bin/env python3
import argparse, json, os
from typing import Dict

def strip_image(src: str, dst: str) -> Dict:
	from PIL import Image
	im = Image.open(src)
	data = list(im.getdata())
	clean = Image.new(im.mode, im.size)
	clean.putdata(data)
	clean.save(dst)
	return {"type": "image", "output": dst}


def strip_pdf(src: str, dst: str) -> Dict:
	from pypdf import PdfReader, PdfWriter
	reader = PdfReader(src)
	writer = PdfWriter()
	for page in reader.pages:
		writer.add_page(page)
	writer.add_metadata({})
	with open(dst, 'wb') as f:
		writer.write(f)
	return {"type": "pdf", "output": dst}


def strip_metadata(src: str, dst: str) -> Dict:
	ext = os.path.splitext(src)[1].lower()
	if ext in ['.jpg','.jpeg','.png','.bmp','.tiff','.webp']:
		return strip_image(src, dst)
	elif ext in ['.pdf']:
		return strip_pdf(src, dst)
	return {"type": "other", "output": src, "note": "unsupported file type"}

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--in', dest='inp', required=True)
	p.add_argument('--out', dest='out', required=False)
	args = p.parse_args()
	dst = args.out or args.inp
	print(json.dumps(strip_metadata(args.inp, dst))) 