import io
import unittest

try:
    from PIL import Image
except ImportError:
    Image = None

from privacylens.sanitize.image import redact_png


@unittest.skipUnless(Image is not None, "PIL is optional")
class ImageRedactionTests(unittest.TestCase):
    def test_opaque_bbox_redaction_and_metadata_rebuild(self):
        source = Image.new("RGB", (40, 40), (255, 255, 255))
        source.info["comment"] = "private metadata"
        stream = io.BytesIO(); source.save(stream, format="PNG", pnginfo=None)
        output = redact_png(stream.getvalue(), [(10, 10, 10, 10)])
        self.assertIsNotNone(output)
        with Image.open(io.BytesIO(output)) as clean:
            self.assertEqual(clean.getpixel((15, 15)), (0, 0, 0))
            self.assertNotIn("comment", clean.info)


if __name__ == "__main__": unittest.main()
