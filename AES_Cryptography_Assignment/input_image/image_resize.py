from PIL import Image

img = Image.open("2.png")
img_small = img.resize((60, 60))
img_small.save("2_60x60.png")