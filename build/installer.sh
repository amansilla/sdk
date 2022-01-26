#!/bin/bash
echo ""
echo "Spryker SDK Installer"
echo ""

# Create destination folder
DESTINATION=$1
DESTINATION=${DESTINATION:-/opt/spryker-sdk}


mkdir -p "${DESTINATION}" &> /dev/null

if [ ! -d "${DESTINATION}" ]; then
    echo "Could not create ${DESTINATION}, please use a different directory to install the Spryker SDK into:"
    echo "./installer.sh /your/writeable/directory"
    exit 1
fi

# Find __ARCHIVE__ maker, read archive content and decompress it
ARCHIVE=$(awk '/^__ARCHIVE__/ {print NR + 1; exit 0; }' "${0}")
tail -n+"${ARCHIVE}" "${0}" | tar xpJ -C "${DESTINATION}"

${DESTINATION}/bin/spryker-sdk.sh sdk:init:sdk
${DESTINATION}/bin/spryker-sdk.sh sdk:update:all


if [[ -e ~/.bashrc ]]
then
    echo "alias spryker-sdk=\"${DESTINATION}/bin/spryker-sdk.sh\"" >> ~/.bashrc && source ~/.bashrc
    echo 'Created alias in ~/.bashrc';
elif [[ -e ~/.zshrc ]]
then
    echo "alias spryker-sdk=\"${DESTINATION}/bin/spryker-sdk.sh\"" >> ~/.zshrc  && source ~/.zshrc
    echo 'Created alias in ~/.zshrc';
else
  echo ""
  echo "Installation complete."
  echo "Add alias for your system spryker-sdk=\"${DESTINATION}/bin/spryker-sdk.sh\""
  echo ""
fi

# Exit from the script with success (0)
exit 0

__ARCHIVE__
�7zXZ  �ִF !   t/�����] 1J��7:Q�!:���e�Z��7ӧ�L�*6���E�ejŶ$�[	��Ѝq�����SB��s/��;�=~K��E2���ɼ���ᦿ��ɱE��m<	mE�Zcs�ql.���s'�gOz[s�% p�<&�����D9Y��r���GHPL���st�N�W�ڠ6��UC"��}#y��~�@JT0+�A�h���$t�"~_>5.��*,O��]d�g,C����h�A���|�c�#��巚��B�9{��
��@�o��11��":E��P�]$]vaA�-�?�2��-���y="K5�U`Y��}�=v��'�\˥sn���+y���"�0��s��2�/�eɗ��'���@|/f�:��9#�1'_?�&|�G�7.v�' 3�=����`φt�!�����i[�_�0y�]���g^a'!�O2�"XLPN���E^�x�%���F��%�Ep��tǥ�<���Yo�P{����+8/�:�D�G�	��R?���|�)���n�Pͱ)4��vzT��!��|��eE%RP-9Pz�4n|Y ��T��&V�pY��0��"Dyrѧt���g�1e9^ֈf� ?���gN���f�UlV���0���`��0A���Xh ��)�Z��aMK���zb�����׌4�"
,��m�s	���	��ꆭ�* �!�̭��W�ۺX�.U������4����A,z����^�qT7�y\?O��*X�,]���}�K8�g��Q��ۼ�S��F_�.�r~��RE��� �3��?���ƮoR�����jan��t�bR?�+���{t�"���/������� 1�$�VI�L]�T2��F�E
�k�,��%*��`(��.ȇ��"�U�F�::����*�mi�@>�~R�p{�����lI�ܺ������x�;&�~Q��h����GXs���:X`�1 @Ȉ�D�)��P���w'����z�C���q#��Y�.��Z2$���������͟-[ܺ�8 �>3t��*�+����0��2�Kn�M�wB{\s͖$��Ԉ�>��`��q�P�M=��3i+�
D?g|��.�҇������i3�y�2@b-��F����\��Ֆ.�$�ўXC��*)�h���%���y�z����R��lQ����[�M}�κs� ^0K�A�I�H��	&Z��d6��l8T�_m\r9��Ӊ��(k[�~��A;�A&^�C�,���⿘�S�/�:=_d��u ��mXE��uv;�?�}�vKzcY��õ��-�cF%V���gFr�M��������$�H�Pr�a��PYlC _r��gs��H�C�*fD���zb���_b���i2�y�~
�b��6'0u�����f��tc�����'ދ��������[T�"I��Q��%���w�z�`1����|��o���-���y�k�x��y����	���Q<Z�'E\
14����_3�^�&^�DS�L����oilEnp����HJ�{��Q~�ǒ�ۢ�d�K�zZMtG3����hP�I�'�~G{O0}n��R�q���K�ř�� D	f��1���W����6�_����J���P��:_�w�(��G�4Yt�����:�1�8��R*os.��R�Y{rb��QY��6AB8�B�����%D'5C���jK�j���b�P�IT���?��j@$)x
Ξt>�I*�L3�z��YJ�W��]�r��W�%ưn�����ϣ���W ����o��H]<�dk�h_[݆c��86^��sK���]�3bu@�L�PN*���G0��1���]uČ��k$rS�Gќ��7
`<,_�1�4h���Lu��*ё���s#^��Whzt	m��ɯ�E���qR���Hb`a���T��Qʖ�����*1_p^$�+���ݖr�3�{��B�M��r��k�q���<�*�β��SJB\6��>��ܧ�b��u�|���$a0$Vh�]:�p �?�����\;��b0G��j�#%�{�z��a�J����A�yJ��J�)Ytqm)谪o��*M�Ocbs�ơܑ������Í^	��!�F|Kä���NP�U��[7�~��l8�˹��8����]�O�)���$�ڰ��7�U���Y��[У�)١��Y0��Q�^�e|4)v�%�wU>1��&�	U�BH�̺k�z'��4�@�&
�Mu�vw$!����9@#��Tٲ���bo�ydq������"�U!���h#(����Qt�Rߪ�?��˾�Ď�a�+39#0��K��u�i2���N�yJ��na���}j�b���u�;����[�3�����T�y�c�akʩn�z���_^Tr�C�������q���"7��
�H�:wc7-+��A��,��eG�Z}xw��p>f��b)H�2;��I-o�+�����R��o�i����y��>����]��Rm�g/�
���Oj�v@�a�T���_vVC��k2	_|mrsLP�&��-]�gu��)�Fg���U��c��+�4�V�O '�O,��r����}�J�;��#�4&���scm��k(IHꬋ177'�Bf�:�J��v��f��P���C�q�۶� (ce����]"_0�'���ad�<�߁H��~����{���P��j��{�D���;
v���N�Khs8�| ���kz�����%�DSfu��Ѧ�,"���_��z�W�e4O6�	4��^OH��-\y��j�F;HIp昰�^�Z�=�,W����<��I��NF�8}���x#cT����}ʡ4�c��n���z^��l$�P�G�Gǌ�Sh;��<���^Pn� �#�tN�1G_�t�a��+�K#�eǯO��Q�f3y�P#P�g;�0��~ǿ��M��Z�f�T<��g��6~���=� ����+x�i`s!,Z9����n� �*��)�!e��v�!欴̄�`#v�N81U*�<�x]���	gьc�u,�V��l`��������i��8�f�+��5�6^Qg3�{��Y_Xa<:�i����4�K��b��]�kŐ�[�m)��g8^HN�B��;�
�75�a��lY�@�*����u�;6yNwU�����,�$;�+�A��6��}�Y�([��V�Db�PWHΒ�3E�$�͈[7�(A4�;��z���O�DI��Jn�`��F����~X��g��
d����A"
��d��z��drD)
|J�����>I��G�C"�SU��VQw/���Gd���D�B�.v#�㾚����H��)�x��i��A2(vb�i�%��gC%�:)�Q��M�*MqtZ<�W��~[�R�i�/�;ÞLLŖ���$w�� gN���/�̔B�D��5l�33�����(�K�b�:+Һ;�F�3�u��=t���1�P�2�ֆg耺�z�Nr�����m0p*p��wd����n�g��{���P����?D��{��6cs��Y��^���G�md|>Fk_��:%�]��O⼫�
�V��zխ�:�8������Y��4�o���t�*�������7qR9�[���W�����0��8�)������&ze,	ϋ�����z��� �e��E���",�����Js�K��l�0+Sm�A���ј3�
F<v��~oⷆ~�8�\�u��n�#��{�Z�$|����@����\]�"�|kNhJ���Z�=q%{�z�! ����˂��C.�KV�%���*�yȈ�g���-�ѿ-TA?�xU��F́S���H dm��7-��C2ʔ4Zf��*�s�/IJ �)���M�^"\5�i$2T�������u؄�%����˵��	�S��z���j�4�x~.��:V��c��J�v����4��_I����a���^1�;��ò�e+���D�i��:UL�(��ĝ�R�mM�9��'�L���}N�,�?�2��u�&�β�h+� J�E)�~�CC���[T�nn"2>u.Y��zIN��I��d��-W��e�z��d�n
1�w$)����_��YRbB�����LI3�K�A/Ê���ʃ�v1R��+f�J9�2/���!Y�A0������$�C�]�ؓ�L�p{��g�瘬Ж��d�v�0:PA|�U��G;���XS�j/;��.~�]�������G���EXa���ƨ���p��m����R�n��Z��3�������.@%]���r���o��*�)v�S���}�X�׶~��[b��B���}[��{�G�g�����u�z�-��N8�(soll���E�Xo�ϴm4�$���z�p���S��O�s�{�mz.%���
L'�{�#������D���ҡ�S��S;� �g�bR=�5rN}�� @WF�U��r���$X��;%H��mu[X�9Si�l'��wE�"�Sc2'��
)v���2q-�{qz �a�LX힥Tn��hv���ڣ�"�)RJF��d Dñ"��t� �#�� uG����g�    YZ