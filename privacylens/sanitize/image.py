"""PNG redaction with metadata removal and optional OCR post-check."""
from io import BytesIO
import re


def redact_png(png_bytes: bytes, bboxes) -> bytes | None:
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return None
    try:
        with Image.open(BytesIO(png_bytes)) as source:
            source.load()
            image = source.convert("RGB")
        draw = ImageDraw.Draw(image)
        width, height = image.size
        for bbox in bboxes or ():
            x, y, w, h = bbox
            pad_x, pad_y = w * 0.1, h * 0.1
            left = max(0, int(x - pad_x)); top = max(0, int(y - pad_y))
            right = min(width - 1, int(x + w + pad_x)); bottom = min(height - 1, int(y + h + pad_y))
            draw.rectangle((left, top, right, bottom), fill=(0, 0, 0))
        clean = Image.new("RGB", image.size)
        clean.putdata(list(image.getdata()))
        output = BytesIO()
        clean.save(output, format="PNG", optimize=False)
        result = output.getvalue()
        # OCR the redacted output. If text remains sensitive, redact its word boxes
        # and verify again; never return an image whose OCR pass failed.
        try:
            import pytesseract
            from PIL import Image as PILImage, ImageDraw as PILDraw
            from ..detect.patterns import scan_text
            for _attempt in range(2):
                with PILImage.open(BytesIO(result)) as check_image:
                    data=pytesseract.image_to_data(check_image,output_type=pytesseract.Output.DICT,timeout=8)
                text=" ".join(part for part in data.get("text",[]) if part)
                findings=scan_text(text)
                if not findings: break
                # Sensitive OCR runs are conservatively boxed as a whole line.
                draw=PILDraw.Draw(image)
                groups={}
                for i,word in enumerate(data.get("text",[])):
                    key=(data.get("block_num",[0])[i],data.get("par_num",[0])[i],data.get("line_num",[0])[i])
                    groups.setdefault(key,[]).append(i)
                for indices in groups.values():
                    line=" ".join(data["text"][i] for i in indices)
                    if not scan_text(line): continue
                    left=min(data["left"][i] for i in indices); top=min(data["top"][i] for i in indices)
                    right=max(data["left"][i]+data["width"][i] for i in indices); bottom=max(data["top"][i]+data["height"][i] for i in indices)
                    draw.rectangle((max(0,left-4),max(0,top-4),min(width,right+4),min(height,bottom+4)),fill=(0,0,0))
                output=BytesIO(); image.save(output,format="PNG",optimize=False); result=output.getvalue()
            with PILImage.open(BytesIO(result)) as verify_image:
                if scan_text(pytesseract.image_to_string(verify_image,timeout=8)): return None
        except ImportError:
            return None
        except Exception:
            return None
        return result
    except TimeoutError:
        raise
    except Exception:
        # Any uncertainty about image processing means the image is dropped.
        return None
