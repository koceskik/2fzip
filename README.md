2fzip
=====

2Factor Authenticating Zip

compile with: g++ 2fzip.cpp -o 2fzip
run with: ./2fzip -e <password> [zip_parameters] zipfilename.2fz <list files>
  OR
          ./2fzip -d <password> [unzip_parameters] zipfilename.2fz
requires: zip, unzip, curl
