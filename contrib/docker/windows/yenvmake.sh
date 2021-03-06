mkdir /ydir
cd /ydir
curl -L -k https://github.com/senadj/scripts/archive/tdm32.zip > scripts.zip
unzip -j -o -d scripts scripts.zip
cp scripts/yprofile ~/.bash_profile
source ~/.bash_profile
source $YDIR/scripts/getdev
source $YDIR/scripts/instgcc
source $YDIR/scripts/instcdb
buildzlib
buildopenssl
buildboost
buildlibpng
buildqrencode
buildminiupnpc
buildberkeleydb
buildleveldb
buildqt

echo ========= Environment variables
echo YDIR $YDIR 
echo YBOO $YBOO
echo YOSSL $YOSSL
echo YBDB $YBDB 
echo YUPNP=$YUPNP 
echo YQR=$YQR
