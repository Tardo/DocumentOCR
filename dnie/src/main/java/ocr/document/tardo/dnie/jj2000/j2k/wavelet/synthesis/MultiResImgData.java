package jj2000.j2k.wavelet.synthesis;

import jj2000.j2k.image.Coord;

public interface MultiResImgData {
    int getCompImgHeight(int i, int i2);

    int getCompImgWidth(int i, int i2);

    int getCompSubsX(int i);

    int getCompSubsY(int i);

    int getImgHeight(int i);

    int getImgULX(int i);

    int getImgULY(int i);

    int getImgWidth(int i);

    int getNomTileHeight();

    int getNomTileWidth();

    int getNumComps();

    int getNumTiles();

    Coord getNumTiles(Coord coord);

    int getResULX(int i, int i2);

    int getResULY(int i, int i2);

    SubbandSyn getSynSubbandTree(int i, int i2);

    Coord getTile(Coord coord);

    int getTileCompHeight(int i, int i2, int i3);

    int getTileCompWidth(int i, int i2, int i3);

    int getTileHeight(int i);

    int getTileIdx();

    int getTilePartULX();

    int getTilePartULY();

    int getTileWidth(int i);

    void nextTile();

    void setTile(int i, int i2);
}
