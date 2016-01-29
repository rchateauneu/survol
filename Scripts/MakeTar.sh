DAT=`date "+%Y%m%d"`

tar -czvf Survol.$DAT.tgz --exclude="*.tgz" --exclude="*.swp" --exclude="*.pyc" --exclude="*.dot" --exclude="*.tmp" --exclude="core.*" --exclude="*~" --exclude="*.log" --exclude="temp"  Survol 
