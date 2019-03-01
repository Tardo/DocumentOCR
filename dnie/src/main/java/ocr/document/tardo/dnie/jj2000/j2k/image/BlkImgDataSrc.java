package jj2000.j2k.image;

public interface BlkImgDataSrc extends ImgData {
    DataBlk getCompData(DataBlk dataBlk, int i);

    int getFixedPoint(int i);

    DataBlk getInternCompData(DataBlk dataBlk, int i);
}
