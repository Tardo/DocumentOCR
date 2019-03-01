package jj2000.j2k.image;

public interface ImgData {
    int getCompImgHeight(int i);

    int getCompImgWidth(int i);

    int getCompSubsX(int i);

    int getCompSubsY(int i);

    int getCompULX(int i);

    int getCompULY(int i);

    int getImgHeight();

    int getImgULX();

    int getImgULY();

    int getImgWidth();

    int getNomRangeBits(int i);

    int getNomTileHeight();

    int getNomTileWidth();

    int getNumComps();

    int getNumTiles();

    Coord getNumTiles(Coord coord);

    Coord getTile(Coord coord);

    int getTileCompHeight(int i, int i2);

    int getTileCompWidth(int i, int i2);

    int getTileHeight();

    int getTileIdx();

    int getTilePartULX();

    int getTilePartULY();

    int getTileWidth();

    void nextTile();

    void setTile(int i, int i2);
}
