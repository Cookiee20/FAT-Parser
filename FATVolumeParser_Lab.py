import math
import os

# A digital forensics program that retireves files from a corrupted disk image. This disk image is missing it's BIOS parameter block and thus requires direct value input.

BPB_BytsPerSec = 512
BPB_SecPerClus = 4
BPB_RsvdSecCnt = 1
BPB_NumFATs = 2
BPB_RootEntCnt = 512
BPB_TotSec16 = 0
BPB_FATSz16 = 115
BPB_SecPerTrk = 32
BPB_NumHeads = 16
BPB_HiddSec = 1
BPB_TotSec32 = 117250
RootDirSectors = 33
FirstDataSector = 264
FirstDataSectorOffset = 135168
DataSec = 116986
CountofClusters = 29246

# Byte function
def rbi(bytes, offset, size):
    return int.from_bytes(bytes[offset:offset+size],"little")

# Open the exam.image, reading the FAT
with open("exam.image", mode="rb") as f:
    b = f.read(58880) 

# Turn the FAT into byte values
a = []
x=0
for x in range(0,58880,2):
    a.append(rbi(b,x,2))

# Will store our potential beginning and ending locations
beginnings = []
endings = []

# This portion will gather the potential beginnings and endings within the FAT
for y in range(1,len(a)-1):
    # If the value before is not continous to the value seen...
    if ((a[y-1] != y) and (a[y] == y+1)):
        # Designate the space as a beginning
        beginnings.append(y)

    # If the value in the spot does not equal the next spot and the next value does not equal the value plus one...
    if ( (a[y] != y+1) and (a[y+1] != a[y]+1)):
        # Designate the space as an ending
        endings.append(y)

file_start_locations = []

file_start = False

# This portion will help us get the starting file locations outside of the FAT!
for i in beginnings:
    file_start = True
    # Check against all potential endings...
    for j in endings:
        
        # If the value equals the entry spot...
        if a[j] == i :
        # This beginning entry isn't the VERY start of a file, only the start of a fragment
            file_start= False
            break 
    
    # If we found a file start location, then we add it to the list
    if file_start == True:
        file_start_locations.append(i)

# This portion will help us read the clusters in order!
for y in file_start_locations:
    # Get the file start location outside of the FAT
    FileLocation = ((y-2) * BPB_SecPerClus * BPB_BytsPerSec) + FirstDataSectorOffset - 1024
    # Create the output file for that location start
    name = "output_"+str(FileLocation)+".bin"
    file = open(name, mode="wb")

    # Within the exam.image...
    with open("exam.image", mode="rb") as f:
        # As long as we haven't hit the end of the file...
        while (a[y] != 65535): 
                # Get the file start location
                FileLocation = ((y-2) * BPB_SecPerClus * BPB_BytsPerSec) + FirstDataSectorOffset - 1024
                # Move the pointer to the beginning of the file
                f.seek(FileLocation)
                # Read in the cluster
                cluster = f.read(2048)

                # Write the cluster to the output file
                file.write(cluster)
                # Set a new y
                y = a[y]

        # Get the location of the last cluster hit before breaking out of the while loop
        FileLocation = ((y-2) * BPB_SecPerClus * BPB_BytsPerSec) + FirstDataSectorOffset - 1024
        # Read in that last cluster
        f.seek(FileLocation)
        cluster = f.read(2048)
        # Write the last cluster to the file
        file.write(cluster)
        file.close

# This portion will help us determine the type of file to switch our output to!
for x in file_start_locations:
    # Get the file start locations outside of the FAT
    FileLocation = ((x-2) * BPB_SecPerClus * BPB_BytsPerSec) + FirstDataSectorOffset - 1024
    
    with open("exam.image", mode="rb") as f:
        # Read the cluster at the start location
        f.seek(FileLocation)
        cluster = f.read(2048)

        # For every byte location in the cluster...
        for z in cluster:
            # Unidentified until proven otherwise!
            Identified = False
            
            # Check if the file is a mp3
            if (rbi(cluster,z,1) == 73) and (rbi(cluster,z+1,1) == 68) and (rbi(cluster,z+2,1) == 51):
                name = "output_"+str(FileLocation)+".bin"
                os.rename(name, "output_"+str(FileLocation)+".mp3")
                Identified = True
                
            # Check if the file is a jpeg
            if (rbi(cluster,z,1) == 255) and (rbi(cluster,z+1,1) == 216) and (rbi(cluster,z+2,1) == 255):
                name = "output_"+str(FileLocation)+".bin"
                os.rename(name, "output_"+str(FileLocation)+".jpeg")
                Identified = True
            
            # Check if the file is a mp4
            if (rbi(cluster,z,1) == 105) and (rbi(cluster,z+1,1) == 115) and (rbi(cluster,z+2,1) == 111) and (rbi(cluster,z+3,1) == 109):
                name = "output_"+str(FileLocation)+".bin"
                os.rename(name, "output_"+str(FileLocation)+".mp4")
                Identified = True
                
            # Check if the file is a mp4 (different signature)
            if (rbi(cluster,z,1) == 109) and (rbi(cluster,z+1,1) == 112) and (rbi(cluster,z+2,1) == 52) and (rbi(cluster,z+3,1) == 50):
                name = "output_"+str(FileLocation)+".bin"
                os.rename(name, "output_"+str(FileLocation)+".mp4")
                Identified = True
                
            # Check if the file is a png
            if (rbi(cluster,z,1) == 137) and (rbi(cluster,z+1,1) == 80) and (rbi(cluster,z+2,1) == 78) and (rbi(cluster,z+3,1) == 71):
                name = "output_"+str(FileLocation)+".bin"
                os.rename(name, "output_"+str(FileLocation)+".png")
                Identified = True
            
            # Check if the file is a zip folder
            if (rbi(cluster,z,1) == 80) and (rbi(cluster,z+1,1) == 75) and (rbi(cluster,z+2,1) == 3) and (rbi(cluster,z+3,1) == 4):
                name = "output_"+str(FileLocation)+".bin"
                os.rename(name, "output_"+str(FileLocation)+".zip")
                Identified = True
            
            # If its not identifiable - then we leave it as a bin
            if Identified==True:
                break