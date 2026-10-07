"""Prepare bitmap and icon resources from the chosen visual assets."""

from pathlib import Path

from PIL import Image


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    assets = root / "assets"
    logo = Image.open(assets / "miocrypt-pixel-heart-lock.png").convert("RGBA")
    ico_target = assets / "MioCrypt.ico"
    logo.save(ico_target, format="ICO", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])

    small_logo = logo.resize((256, 256), Image.Resampling.NEAREST)
    black_background = Image.new("RGBA", small_logo.size, (10, 11, 11, 255))
    black_background.alpha_composite(small_logo)
    black_background.convert("RGB").save(assets / "miocrypt-pixel-heart-lock.bmp", format="BMP")
    Image.open(assets / "mio-ransomware-bg-denoised.png").convert("RGB").save(
        assets / "mio-ransomware-bg-denoised.bmp", format="BMP"
    )
    print(ico_target)


if __name__ == "__main__":
    main()
