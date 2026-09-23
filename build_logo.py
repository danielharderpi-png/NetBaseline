import os
import cairosvg
from PIL import Image
import io

def create_directory_structure():
    """Creates the exact NetBaseline folder structure."""
    os.makedirs("NetBaseline/logo/png", exist_ok=True)

def generate_svgs():
    """Defines and writes the raw SVG files with the Linear/OLED aesthetic."""
    
    # 1. The Symbol (A sharp N intersected by a glowing blue baseline)
    symbol_svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
    <rect width="512" height="512" rx="112" fill="#09090B"/>
    <!-- The Baseline -->
    <path d="M 64 256 L 448 256" stroke="#3B82F6" stroke-width="48" stroke-linecap="round"/>
    <!-- The Geometric 'N' -->
    <path d="M 160 384 V 128 L 352 384 V 128" stroke="#FAFAFA" stroke-width="48" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
</svg>"""

    # 2. Horizontal (Symbol + Text)
    horizontal_svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 400">
    <!-- Symbol scaled and shifted left -->
    <g transform="translate(50, 50) scale(0.58)">
        <rect width="512" height="512" rx="112" fill="#09090B"/>
        <path d="M 64 256 L 448 256" stroke="#3B82F6" stroke-width="48" stroke-linecap="round"/>
        <path d="M 160 384 V 128 L 352 384 V 128" stroke="#FAFAFA" stroke-width="48" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
    </g>
    <!-- Text -->
    <text x="420" y="245" font-family="Segoe UI, -apple-system, sans-serif" font-weight="bold" font-size="160" fill="#FAFAFA">NetBaseline</text>
</svg>"""

    # 3. Full / Vertical (Symbol centered above Text)
    full_svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 800">
    <g transform="translate(144, 80)">
        <rect width="512" height="512" rx="112" fill="#09090B"/>
        <path d="M 64 256 L 448 256" stroke="#3B82F6" stroke-width="48" stroke-linecap="round"/>
        <path d="M 160 384 V 128 L 352 384 V 128" stroke="#FAFAFA" stroke-width="48" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
    </g>
    <text x="400" y="700" font-family="Segoe UI, -apple-system, sans-serif" font-weight="bold" font-size="120" fill="#FAFAFA" text-anchor="middle">NetBaseline</text>
</svg>"""

    # Save the SVGs
    with open("NetBaseline/logo/NetBaseline-symbol.svg", "w") as f: f.write(symbol_svg)
    with open("NetBaseline/logo/NetBaseline-horizontal.svg", "w") as f: f.write(horizontal_svg)
    with open("NetBaseline/logo/NetBaseline-full.svg", "w") as f: f.write(full_svg)
    
    return symbol_svg, horizontal_svg, full_svg

def build_png_stack(symbol_svg):
    """Uses CairoSVG to convert the symbol into all requested PNG sizes."""
    sizes = [4096, 2048, 1024, 512, 256, 128, 64, 32, 16]
    
    print("Building PNG stack...")
    for size in sizes:
        output_path = f"NetBaseline/logo/png/{size}.png"
        cairosvg.svg2png(bytestring=symbol_svg.encode('utf-8'), write_to=output_path, output_width=size, output_height=size)
        print(f" -> Created {size}.png")

def build_special_formats():
    """Generates the ICO and Apple Touch files using Pillow."""
    print("Building .ico and Apple Touch Icons...")
    
    # Load the 1024x1024 png we just generated as our master image
    master_img = Image.open("NetBaseline/logo/png/1024.png")
    
    # 1. Favicon & NetBaseline.ico (Windows icons usually contain multiple sizes in one file)
    icon_sizes = [(256, 256), (128, 128), (64, 64), (32, 32), (16, 16)]
    master_img.save("NetBaseline/logo/favicon.ico", format="ICO", sizes=icon_sizes)
    master_img.save("NetBaseline/logo/NetBaseline.ico", format="ICO", sizes=icon_sizes)
    
    # 2. Apple Touch Icon (Standard iOS size is 180x180)
    apple_img = master_img.resize((180, 180), Image.Resampling.LANCZOS)
    apple_img.save("NetBaseline/logo/apple-touch-icon.png")

if __name__ == "__main__":
    print("Initializing NetBaseline Asset Generator...")
    create_directory_structure()
    
    sym, horiz, full = generate_svgs()
    print("✓ SVGs Generated")
    
    # Generate full/horizontal base PNGs
    cairosvg.svg2png(bytestring=full.encode('utf-8'), write_to="NetBaseline/logo/NetBaseline-full.png", output_height=800)
    cairosvg.svg2png(bytestring=horiz.encode('utf-8'), write_to="NetBaseline/logo/NetBaseline-horizontal.png", output_height=400)
    cairosvg.svg2png(bytestring=sym.encode('utf-8'), write_to="NetBaseline/logo/NetBaseline-symbol.png", output_height=512)
    
    build_png_stack(sym)
    build_special_formats()
    print("\n[+] Asset generation complete! Check the NetBaseline/ folder.")