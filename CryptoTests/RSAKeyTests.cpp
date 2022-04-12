#include "pch.h"

#include "../Crypto/RSAKey.h"
#include "../Crypto/Base64.h"
#include "../Crypto/hash.h"
#include "../Crypto//OpenSSLErros.h"

namespace webauthn::crypto
{
	namespace helpers
	{
		using namespace std::string_literals;

		static auto modulus_1 = "vS7ZOqkhI6uyv3AyS/BB8UnsgQ6cpupvyjXdPGgO3b92jfcKYjwJNOz3rShW4Xd/DjUZB1aJia1Ca7LfYDLdankWwUK53JcCWCaLxLIwXN9tb84DP639pORlDcnH0gYB404+WSbtgEYXvGwjROyDIJgkla5fLYq1VYF0uFcJ4BvAPyAEYDmNzRorQyT1CV5Kxg1BOYHURXF19yhrsEEvamZoPCYt0Ge2KEgW7SDXoe35jV/1ZL/py3vUG4SaKkWf9B8bf2Yesf87jh+cR4spGes/7B8TUTvkXFyFVW/KYqQcxOWdITFoSU/PYXM+6h/wC23HxpJVF2mk8m0IGatlCQ=="s;
		static auto exponent_1 = "AQAB"s;

		//e8e8a03067e43a255faff34586d87ae7fd7cb758710ba540f354b0e4f53678920500000001 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
		static auto data_1 = "6OigMGfkOiVfr/NFhth65/18t1hxC6VA81Sw5PU2eJIFAAAAAWZoeq34Yr13bI/Bi46fjiAIlxSFbuIzs5AqWR0NXykl"s;
		static auto sign_1 = "CVhqr9g0fIJdRyaoonfS2LTJrEt98OFkaateeApnXh98r3VvlTM2QdLDb1vZls0nw21um1sK7h1OOG0fD4pKqKPfwEFEaSz7fX15P95amTF9ZFs1gqsogD5SFFPyHJWbVu8+57oC7hzBVtY5Y3HTewDFxKFqU26qo/U89T2L9BU+qsZpgQRbnz8y80I0+VEKqzpq6mZQMvlksDqU9pcjdtyM46IAZsWxGJyA4wP2jhcGNfuqH9/MPCJfMIclFJ4ZbByNQ00qZzHU6qXr3ZQDa8vwJnzkVkLP2jzuV8kwbK0jbYRK3ndX+4kXLvFN8HmP/W4WoaydEv0LanVucqNCoQ=="s;
		

		static auto modulus_2 = "AQEAqlFaiNehCMCkEcdF1DjNLYGtuo5MW1ZqzHuGl6+fhhKtGnf0IooDok+tzQYrGLXyx/aHjL6QR1Q/nlzYZAEgCJHbOt1UoWab3R3baAPIQg5uyZqQJm8jeiNjPMco86/D/NI1rt7Bp86gkTD9tEed7097yIODLcqhPecNNpTJ0tdTtsh5t3DscrL6DXSFyoiPPFDbKVZ8B8tQlaQXGv9T9wwpEaFpKPv7/RL8cq7sA5a0RN4AOKiDwmdfO+/CY50hkEkJuTG+Zpjc06+QLufShMMNJBfPpgzNzgdy2JQeQWD6jjcc0rRSh1GeP1keA0yOfbb4R2rWARhPGe96ZUnRTQ=="s;
		static auto exponent_2 = "AQAB"s;


		static auto modulus_3 = "87Y+PxFiiD1dcqBBcU1CyCUBu1jxdYqaNyQ1mAZBZhjs+737Oz+8xGJ9ZDHe3lWmNdSFHfmC/v6gXRLRMMg+TDMbte4iJ9LrSTJ9F6eTZAIvZNuStiBQqwoD65J9QSpD1V61z75Wvh41xYYVLywIfOEW2jGqFiBOEZknjwuT3SOEB271+TasrbShuacTN3ZSzPABVKlewLuSwQ5yVa4jNYyGwwiZzbHiDBhkugNY72ec5UfH7qT4BaE9dMoGU+a7Dvt2ki0Te4xUGAde6Zs5x9EClJqp62qntm4vv220R229RG765u3sTR3O4jZScJYrVZTXLoQcSJfS7c0elI2ydw=="s;
		static auto exponent_3 = "AQAB"s;

		static auto data_3 = "rdfajgfjhuiernyviuynrfoewiauyt97wtyo9ayraichnrtv9pw4t9ny8a64rtcboe59yw49vbto8w3trbdxg86wcbtvrvo8awyto7awo8tb8ovnw94tb768vowrtc87oyt97wa4ty78ovy9pt7yatvyap57nvy\n"s;
		static auto sign_3_1 = "btXlIHynyVlclRefNkevscV0EqvQCH9pz7poFe2pQ3j1Cugu3fZz5KUsfEMnPmFcLuMxh7WzO0uo1knd9vDwk5KTSSSqu3ToMUKpo8+uxmbqAi6Nr/7WizurHdIdEVNgZWLBwPIV4V4J3IB9myWi1L7BWvWzyTq0HNM+2gZdqZou1qpT5kNLkeTKCjesyJs7+Yw2t2tUR4VBIo4z7Q/5tAna28ioDBn8t/lJIuIQBA1IsL6+tdt0PkREw9Ch+IHDxBAMHUfwZSIrq2MIcnM562DneombYwE6LkX/NkyjaTPXLg7gQib4s9iBc+CbJ3sTGL6SE5pkSf2eSW7xqp+qAg=="s;
		static auto sign_3_256 = "qWzwJSBPxauesUUKQFu4AzVLBi9eadkLjCqfGTQE2BP9Lf3UcsukoqSxGym4ybB+4uS049qTA41GHWbBN7/W5ThQPEwLHo5dbR3VYpWYzt4eQK87J8J2Rda+2aCDJ9SsrN19JEftOlxeaWgzbSXR46ycTKFimtr8/zw01F/jLIxxKHh7DJ6Ai9GqdOdQvBk7I2y2cW/G3+JTar1s8T3yIXB4wZclWHBPtmJv6QvbD28iedQrN4NA4NIKCnUQvWrjV6VCPNA+81iLULQLDve1+N2bHXhKZg5tw1PQgb0vGFsi3bZL7BEISDjd+hxrcIWpTq22iVrYIhAuBc8ckRntfQ=="s;
		static auto sign_3_384 = "EKAOUTngdUMkIT6L1l8s6FeT0QGRznauglOXZyWJr/GUk6OhQJPb9q4n144EpvWisWOhDj5Gq9WoHSnHuxiIYZrOcExE2chAsL11wMO1ct3IhAGe+WZp/lXe+7429w7pyHDtwHr6AOEH51JeqCn9o/qzIP5F/rIDwJUmQRdp5S7VbL1V/7XOoauOBo82xpAOV6tktkJeYJjpT5LrIrEj6bUCzs6R+F0uQ3+ygtWMFxQI0RcuKc9zOjsbs978y8QfRpledFlVNlOSwxqd3TYozkiCqfbmHp8PWyPKtAyb4JON1Sv8lge5t7vhJiH5txQFU0v95fZRlDTI2/4wJ91UIQ=="s;
		static auto sign_3_512 = "uYGfnmd4/wxR6xZRFMZsYlzsS2yp/dc1/Gsb8Lo3azo7o/stgGxNo/ZDuDcevo3uMT7T2vHet/KClgRSW6q7jQD7bCor/UdNZ3XfOcIuVyBlkHZ/a3ERnSOwjAqXH24Wr4dFppYbZRUGybi0aJZK12bTM/JAv5Gh86SpTGBQBSuVWNU5OC5F3L2FQIHT0AEW4YMYn06bbbUZw1WUvyW/Ye1JC+EXogE+b4GwaqNAFFcToyR0hbqbJvBnho24HqJ74KdfTjFeLUn27LoUyMMtcxaOiEbZ+wff5viOfMK4Udz37A2uYVqVeecvln06Qv+hSdiE127G69A4Izc8CA2Uvw=="s;


		static auto modulus_4 = "oM4u1cSr7skfnidIQhEkUPt421Tdy0nFJ1YMP47AoQDA2oB2FvpQG0P8tCJUbBJZf1TmYQxiHDHXsGN7Bm72HxWiGr4i5n1zm82HgN/ZzYxCg61kVtdo1mjDU3Cxl+J1WP1Gs1QoyGJ6hA7dx/GFz6+7yfyd32VVrgJUbs/4Ip/fp5e7K0b3GuutV05syZ/ItlViL8cMWrmMtO5MkvJ3I2bXQatyuwmXFPayDWGv9DzFVb6sVz5+GSH82Sxwl89+5RD9oBqaYVQN48++6ybXvOWB+CmiCnUba5eB6tpCgJ9PS3xabzGYKk1fiy8BEc7Vw+ii29BVPDG9sHZhSabivBSqMIIiiklbb/SXm53SIJhP2ELd37Ooc0hSyvfKgcNo9qFdzY+ShszYBjwZAk7Iimq2Fh74ee3eC2luxAu+gwOHPvcxmcLj9+Gw8WjDpWKr4NT/UHR3j2OS3v6tdF09PxIQr1tjg1ubvPKOJa87qfxVsV2uUIjY+33P6exqoOEH"s;
		static auto exponent_4 = "AQAB"s;

		static auto data_4 = "diyr98w3y9832uyr3y29ry987p2r398wquryvtov75rp-7rv36yt8vowyrvoiaychr8o7aywbr87oyowe87ryv8w7ovp9yt8bg6cirt479toeysto87way4t8o\n"s;
		static auto sign_4_1 = "LTOqUG/fwM0tQ5hCeGbowgmhnO5uno0dMeb0BWKyN9dNuGBRdVjmEnOZ/GJ9AKJu0bZYtfO5z46dAfOSstCLYZzo9DvDgdgygwMKLjxrFFbW1U2iYBDYE3T/9c3OVhZRM8HKXfEEqMwQfEsQIpEP1spxV0KNW28z/VHsnB25HU1auajVMMuUVru6VkBnGyaSUl7pryzdvo8quiKjp8IzqMXK2wvRtzDaI+BUqQaIT1f9KZqn5KYdeemiuYSrc5IeupN8GE4jIRS9/Leb25xgH4IOgj+k5y7Xp1T9KnvHBf1kfBKqLqAvpZN17a2L3MC7gGnMmCnUyvb6vrk58hCWvVgD+ZRVY4hHQ0HyM58NdwK0zvV8jHi9nWS7wlur/Qicamz7OEn5XBeK48E4f8kxB9zSYjTzznpZx5DTvjnT8Lyq9gj5DtiC3ZM7AGKS6yNsI1275ORXJD8kiNlonhuE9+Ff41XZ62qqEqB3UAy66+QzVhh7kIAHU2zM3eYshUzU"s;
		static auto sign_4_256 = "aFifoIAOL7TCxE727skEvUkUmFDR0gix5X4n+NVFCaKGkzuhncylkED5EA/kpDoHzRfTzVSu3cDBIjj+wYvcwf3Xt6FMJPGT7JrdNwXu7P54Od/NsSrgqdvl54SL86bVoATt8ajXHmFo6ciZMHLej5Ur9RslmNYyONGeLO1g/xeNS705L/sD+bqk7DaBeFI1j/rGKxkmu1d53Ty3IfLsKPJV6Uc2wkMkWU4ivd2TSuJ5Wn9f6eRvlgtXQYAuuAYNQIkSe4/pisQ5LNvYJcbrEhmKlR/hUbki2cDmxpNM5qpE5MBYAQQgrwKXxVsIE5XGf1vAIByVAOJn25UMGE1wJNI+jooOM+9YccV+/LIRNZZES3WnOjbfSKKjpaDFAtbdU3kKk7hbaXIUgj0aeaY2Jt2g9H2vYDlnFzuXK97yqhpuEtXqSvp9FwvzXduIBThl0BN7Mvocla506ZoeqVCr+SFLSEpM+sZ3mP8iwLHihwk6XR5A1hydZCu3bmOZW9JY"s;
		static auto sign_4_384 = "f05QDAl4KcgyUVfRkuIbSmWHMLdjhXzNHenGLURjI4Q+xqhmSQEuB9Xe0Y6XqbVT4otb4ziJSy4ODx9cPqccCGe4Pd2Bv9OZVJq/S9gEkxJVzECoWtr+1RfLEnfWSyvpwhkTh5SYS3ifrI8FnJZiIlIJyirZU/7KqzBmBtZ356UQfJzS+JZQbI1bpRGa4qC/dg1UFGkgDgOFyKgt3955JAFU5AGtfy6+7kfVTKK3AvtGiNXOVUxuuFtXgBR++Hy3pFDgDcLpH9Qhu/YT7sTAc/PBy7dRsLgxw8uOBlVKSvFVaA4NB9/q4Rrt+kXwkOBl7NgCt6dk753xFkoX6oHp0iZzBFGLdMUAa5bVkkx2gaQoXJohbJPQZAnye74bjiphaEPmPQ9V9fvEvbdLNFwTQozKFHBn3bbn0p5nkPCleQHU/mc/cCwe/AwPRlE7FuWz0aDe+ZeXe6vzooYfIqQT8MzawEsDPULfu31DQPZHqFQFQIu095dMnNyPFVUoj/Mg"s;
		static auto sign_4_512 = "d/ppJtj4qGGrIS0hHGaCfVtucSylYrbK0yZhNWQxoh9mQhChtq5hXm7cskdZlFUcPhU/jCzLYzSJ4V/G/smLEcgHEOE7KasjrJJbrkDJAu9368rYXq0tzT5Vb3dA1afl6iKJASF/+AFtPzsnWzMMvme6Nv+AixjgzbolekDsHUppeRrUkUozjiOMj0MTBupxNS/yeylY0seEAMcY5WxPpFmaZ/tmE19A2Oy++tZEhVZ9fUWl7EJ1k1VcqTio6xn27v06yCBQMWBF/b9BMOC88WC8acnYZnZa8Ak2lSG1x5H7rxjkq5h5zhHDsH14s95DMeh0Q2BtdhnyJoEKVqoJ+V3nvJm+8XZfsSzkADZvHb8pXCMmM/nF5I88rX1xsL/SDLi8JLAxssVOGfMUhMfDw+9yVaHW4HKzcxqR8et0N3uO3JyHhmdwWk6ObGhpSzRmnsExDYjUuwyHHr8i+p006bWOTsXGU8Kp2K2HVB1ctLI8rJN/aAIlgbQOck1wCv7H"s;


		static auto modulus_5 = "yp/Q2xT1KzIt8GlEuuJ4LzpL4JkgiXspdceYEaL6e0W8VPRc65lAEB+r9wH9piPzRCRCS4IC3f41ZL8Mv0YeapC6qVOZXFrnqdPosg3U3BqLR5Q022LxktetzM8dD2CbneD834vLyiyU85ttUj1d5T/67zDDn8h4RGHiqUxZvleBxZdymVsVivNgxOLDN33Sra4hSBx7KI6ynLXQuZ8w1d1TwFw/ZiITActzWC1LrB3nKvOfAb4wLb1cfq/SpUrTLVuXNvzPFNwy0GXKXz4o58Enl2tElkvyk5uMtKxT0ulqh9JNerRk2Mev08ZgXCKfaoP4BBvsTAEtlz3Pk5joBfQFLaMKuoaHIk3MWerVFbw7hCOp7a0QIzwLZiH6te0MCf0f2/2b/2RxIKNRAJsn4VKts3GHGSfaj0RHl+0SW2u0NewY2EatFS6N8mu4HuXgZKVzx9sHjSy40Hg/gHkTqe5TgAIfKqNoDYm0tUJBg+9OfBaP9byvoxXGUPotydU13Xfi4gqy6kx3InOkpiF/4OKGh/pDubieOGySI8XoqBBzOUMty02FD8kUFp8viOlMS5tU9shuW6I8xUoSfKq8ccSsNJDKqDt/BggTk2wvwaShjJ1CdaqV2fKpINtxy6oIM7KjEPMghMBhcAv2gp65ixI46gjD8f6IMrk2leTsJ8M="s;
		static auto exponent_5 = "AQAB"s;

		static auto data_5 = "uiodyv79y59t8r34wy7ry9w3784yr5vweyr7tbgc8y94wyt8vye9d8ty8o3a6y59r4w987eyt9oay7tv784ey7t8voy\n"s;
		static auto sign_5_1 = "GDxLRQjdVla9mFN0ID5SyIwP4mRiubuh+56RgHY9qib9blJJfvU/aK26lU37kEuiSsDI63I90PBeKdPWplqfM1V6E/2fizPwX7CK5BVlGp5sfrUD07wKhUZhULTgAZGfSw+46Liw/xLn8EoL9iiwJnyITpLi1xS7RvU/57OfNObXpvZGyNGVA0GxPbudbeNdmfMmxQwrr07YJpgY1gOMohlbEQhwlG6+AL3KMIwnOQbV2nxRza0ZhKOMf7zZW4NvkNV33+zgqslKuUsrf+bsfY/jepzxQZwJvoLVU3tb+Csvpi6z0zp36m23qpyfDY/ZF1uVSjnf5Benfp4FlwIYLudRtA0PJ+5x7YUY5W6KYCphVdesT8hB3+My+U+t/jcYSL3YuqgqpliUZGQUqrFDMLt0hw7pzrjggEL1ZJixYmjnRnLMvY4TINrrO9iaHEW0L/bWVeQSVExFk22skNVD795DONBIs4WLZrL5H4YnaDjTLr04YGoXc35OXmzeiE1GYiVAlXNRP+qUNTHMuB7eSZgXBVuWZXsobbAtgwH4Ng2APo7Ic18KlkX6pA20h6Xfj5z1nhwh8R7v475L338EAWX+ltA+uSMffukg4hZT8+v0t5Yo+HWnrtcWLkX3kw08ogvlwgOtIRWHDlZAkT5Mt8mEAwm/7uxL3DADsS+cjm4="s;
		static auto sign_5_256 = "nUjMnKw2Y91Xd46YHAr1K2GjKIwJhXqr1yNd+du0BLXKIQQDu3JUM6caOsfXSSgyqZLwAEb3KyIE8oDQKoxYLn53s/UUVzjzPL+lHzii4qQCLy2yvT/n4BGL1YGwAmbASRQuaAxnOsEOfPVJaB8VVOJu0Yc/sC8S91NIoY9juv1s1zG1+q4lxE3YY9/ZMHMTSYIzEYvFDCcTl2jBwbIomR8/zwOuqNcvgG2okhECjyYkHfNczuCO1BIpPjjNDWcgTOqTcaAnSnIrfAP3rmIRRqxqdyrffBWzhHV9q4MV6zEdZcGNo9Mn9Vqf+iCUfjBR56DidjqLG7tEAGgR2h/iNSq/r8UkEeGbza1PGqNbO0STbPZoZ4Mw0G35UJEXe2VSgBbDXyvPs6FpiQeEhgVw+EL0OmObEh0BiEBDcbl+PebrfY33bdFfYviujAFCYSevm5GRraRsprOlH5K/vM6qFVtrxilFojES1HX9pCZVMqvhZqtUIq/aO235cM7Haw3tIXt8xUs2WlQZSl/SMVhO6wX6GSJqomjgyu28G6mTubxxXK6W2FCh/YMkNcuLGmGtTAzyvlpdDzampc12sNyyHP4wfuwyX0dPDwewv9I3QFYE3UAv0ZeR4VyDeSqHl5yRML2KGb48QGpqYift4hUNIkuGF5qP5AvTe32mMI+7QTk="s;
		static auto sign_5_384 = "B7tFOkgXg17it8PsYXSI8C8nZaHMsxYXeD6ep3oHQHhQpRNiw1hi4ZT3B69E7XsPrbybUt3rg++3bSSMnIuKZ3yVgajx0s6OE3ORxBSCFiDGO3R0chfwsm3wFji4tZHZSJQeCT8v3CmwjAfqkV99rnaYSUFRJGgstWZGSGa6QjTcoy+y7sfcNkK+LsNo9cedMCR0g9rD0v1q3puIvljUE90JZXY8jqR13kITWMRQLRdRiA0altuvv8gRMeItFJ9iWooWN/VYghEImVGA01fGvJqAlLajVyGdNnLm0t0UYJTtmxhUsC24qXfKsnAO9EmbnyPGEurx2MIWb41Mc7+ex7AMFmdykUHcyIaJvdsuNE+MhOC6jOrulxwOxDOOCCJMtw0I5zIbC9BSRkdFxWJzQ+DAhp09OF3xtF7TldVTgF/VZa39jX0O0Snl/P2vpiRVS2kBJJkccZU0cmUT0M3wFJlYPozXpQYm4FdzJx3IhhschPz2B3WxV+enrxB+I+Xtdkb1hlf27wIk1Lj0YXyO45J6fbJupVhLB/g8XMyBlRfDeLZTZe8y31BUzRKS/XK4LwraGHzxx9OvPRwWiPHB8OmR+XpCPoAKBcwaEujzGYbr4aYnJeSYfDBJRlkDnKaAlsNj6vAYZJqzm7udODbzsqnnQFYL4DniazDFpHCnj8M="s;
		static auto sign_5_512 = "KF27QCeHPjpDIVpCHNS21NKnGQIGihpkaMUPXZ0BTCk5crSBA4Ji/+THZwS2mHpRCKgqA9lkyh7mDlT1tnz+KvsYQk/Qi/hoLbSTZmXUMZGhbvy+xnzlsXkKMWH+8ZHdCha5OVNHBqauY64DAaoR9BZZd1lsM741S4XTKwELwyiYvHTijueTOrUJJXbpgSAMyb8LAkW8fCFkTEOb7AJH1IvxF31Dh0az9JTP+tNPf5mGnHkwGpikUBsKyAluex78fi7iYa/zWDfRt3yBjUXDX4ajujeVmCm5zKgEY/T+7Ul7ppfaW/v7qPiVL/YIc52c0nYQcR/UMFqS5wF4TBwFlCi+PfxcMuBmdglYFscgb9yY1cdjBJzPhDlxfVyfK2f5q1tEmmX44X/hLZXOqQrW3zQG9+qI4W/OqEtqnW6taHk5wD47nh74R2JJ9GPvKRgaRY8KW5He1KmSLR8CM0XSAh1cLj8WOOVmlAUIKjFDDqkR60xtQOvfJeWis2QNun4zwuKKP6d+EwB9fsinUVn6gpodoRAanrw8S8CLsDxJpX/U936la2SAQwUII5U3Xt4sMSSZD8V581UzR8lW08T+OUh8u4ZhBhT4xLVMrApyBBE7Hc16QBLdEBzoVhBi/hoy04ShTOeZnWrLpEXC3CikrYkNWPL9BlEs5nsMcExO0uI="s;


		static auto modulus_6 = "t1jcqirHap5oZfZi3ikyA4D2WouHhvSXlB36W3XOthUYMLNJylBM8QO5Bbo7tMFoWDzl8IvKpsnUSmq/illgamXSoUicKpLfkdCfM3BJE5GwhJuf9lNkLxBMZb9YfG+f1lGLgVxR3Qw8tSeUfhfNsOYbOybB+bw3roIutTcWMFplLK+jip0Yz8kQehG2peZlyDPAxSJbz9FtSDNZLN8BgRa551TczapatE9/6Y1+mM36NyX5zx3aLBii/pFYyg6Wwhy8Ph+9ES+fAW0i58Yzqnmw8/B/Sd6YIg20o3nEAD6c2T385oLMTyJU8lW69zvV4RUYEqzY3DwK5tfqfAshdZcyvwaEUY36E9ZQxucMd8WOn1zeGXy4r+K2Vo86NTOg8TNYZA9uD6G3aeL9HnpuSMJYug7HbjTIzuKhVyfA5YmIS0W0c6HKTKu9K/y6/mXUtDHLEVxlTr34ck6QN1bOPn2jqkMTK1a2ziq66uZSBWIVBWMI3ikj1FHQJNPfMzXnkSo4YZx1/muFW/eHfGkii+n4IEG+oWNGS3MJu+bxWzduWw1IsRc15dFpS1szW8ilOVi4t5NoBHGraMX3I9DiVafWznDDIuYNIdL7j38bFlCo47gE0kkAUFWzQcC8zz2X27o3Tamq34i8CaIUvqTPY4ArkiKyaDx1D0KJVcJOFoK8M+pz3UcXAuJWe+mZe4cRVpvvAvw2O5mMBjtfbTTt1Tvp5kgpsR1EcqTBnXjLnRZYOVM4lgZX5lLwSAS1IZuB2ZJ90/feQ+G5yROtTZsK44sFk4mCjkc3AfH+zeJVNBuueiSE12iOKmEHzqPgFojg3tF0L8d9P0CR7f6iVppwo3OLZ/DqlE7GETu59q+1JqITsgJoUNu0E8gxhIuQhVDBwiq3+NmQXy+mLL+hM9njl2D+8jcZIy0nH3w3fXSB+oZhDgu43ue6fICh/NAYdaYMzTCW4ee7xsMXpVPera0Q9+dV/Moah+6wvSFE02bkFMjuyTSgyMAoXhaodLdOTBBmOgaSgpOSgXhAlTBvhw+QVjRQNmmlgWH2aATwGuurIA6fOrBETpuiSVAONOWuDJdnv2Dt7HpJhmaicm7e0otQoSEQEV+TSDrEG574Ku0XP0xkD2KW/5k1LnrdXfK8cCcYAPbeWVf+OBghYOdZjZPvgQfpRNhx+tpTJc5BQMsk2UWPkZLrsDVjSpIJbJ2GQftTdH5x9TK7Bbqo3ymJholpAvnv4qssjXk/4HRF6ahpjrqdJcshUTqVCOlMEQWXWFkPtVaD8czIje+mEw7GUUuiInkOYtowZ9mZK+4CD4T5EHYWOQ5JZNlN+TqGRWSksMwDO3yjQeSLfZWj2q6c3Ozo1w=="s;
		static auto exponent_6 = "AQAB"s;

		static auto data_6 = "kjehdf79vybryb3w89r6by873w6ry9823r2ywy9r67bw3oyricsytri7o87ayw98brcy978w4rcuo8y7oc67c4eatyv87oesy\n"s;
		static auto sign_6_1 = "Azd2yIWkRUOzti66KS02KzDOZbcMN25eQlK+WgxnWZHMVuN7BtuWLZgxI1NZ5kOe+AvpDc8KQI+eX3Oc1P5mLoHCZQQCVSSi1/OWvR3mt5VLVNo7DEuZwB00jV4Nl/YnKlLVVcwGLAzHNDeD8/Pd+/piVENU21UhiThU+PTop3ew2XSIf47BtfQtSA7bzanzKEJo1hLcmtNkSFNOFpLlenINicALUepBpGDpHeO7zl/kMEVAlRGUsydh2i0BIcH94e/mgE5GUvbW/5rGmvG1Kn04VkTdRC9XQwyRA5i3eZWc6FvOM0mjcReS2rDbJDZvktk20uiWkb23GQKAqTT2JyLE0QDNxwmGUG/BVDBFqM4Mdzmxv0rQglbAwxY9ss5mPcPGQZT/r9IGziN6x4qnvS38UpIQaHKuTsLDBv/lq2wqQl87W2fPJzbajBMrbiL8CwlminEQLtA7xx7ZEWCb1VbU4nH0egYfbdzKfZK6YhB3sR44Lobgp9rG1tsKAPPxjq9QlSACN06tDlupFxTzVyjiwj32yyJhXKh3hUOuOQ7I382fRcZRqahJU2MGMSs1s8NtQYPeNyWK3+R+JiNKxhA9KMVgX+iCVbwdsjD+wZg/n+vhi9oJ+Rz/TrWePv5D/fa30XgewFuYUEwL7tH+3VUVywEgeh+nE61sB7mJ7wCCxeoUHvs2Y3ZJMpY9UzD5jjx+5g0TdTqjWS+/THE+HVAUC7IWhlTgrK8FuhBYo6N3AnH6RNCB3Va6/QUYcS9j9+ByfyAjgnQPXsr9GO8OmveMcphwZsDwSf/9rJ6m9a7j4oq3wkAysTVKdcVmZwabWiS3zdIPAljNou4KqEADI/Xv77O6ycVXGOha7Nd2vIKfEMBi0EtG3sPoDYUcDjefAKnX10W+v1qjl4cWZM9h18e9bJdfQKNYw3JOkwrQQ/7oDRafpQuQIm1AkvyD4hvG5oL15YtmGpLwMlnxz2NMo1QhaTe2+2EzuobfnMrSjFWEm1eeoZzWUBhN2zEBA4366/Ca91afzZPJttfgc9scYZLQwRc2iuBQyEwTl+sVf4gEa6GQBUW6tlt8nCFWzHplyiVlDJeYbnKVQv6SbI2Qf73Rakj3jrhXsYkrwrE09bCIK6k/D996uUYtgQMdBHqzQGO03UFPX4PFNzBPrG2pTAGybPP27dEzP1XQRSQP8U4ul8Dd08H0Htqv+QY3fCulZJxdLlpyZTsKnO5EroX7v8p8C3wAIxGExsGgkywyuC0ZxQ97uC6QVUmA8nfGVNVYSVj+ustG0I1SKML5wC1uwzs78dzS6S5ND2er64LCBwP0AxWZw6HK1spLaCxSalWj5CviRs6J7/10ZAQg4sg/zw=="s;
		static auto sign_6_256 = "cgJGUnPv43MHouS4l+t9LQefX0GTsr4wFYOG5MnbpBKgE3gAs6m/qBapsG6l+j3KeVbKpJBBr1cUeoX9i3/GIdbwOOf1p4gY1Zzj43MH3RV1XKHxGJnm+TXS+Z790rm1yyhTHumGA9DFBIqSnoOH1MuowvW3L0Xsbsp9Dvni1QtQumLTF3pp0ssV7W6Ht76OzI5WZWwU/czRWJAx1AkIp9hu1ODe1CYKhfwk/JG8ZrCkeZNnEf61tAFJoE4emWINWhh+22XhRyWNEkZlh4TJFPkTLhM28St7C1o42HMIcom6D8wemmnWAZjcA9DFv7ys9Y5wUIF03hIWVHsYxLKYFnuYhtQnTPwerDjy3o6eSW3Yj1/n6JrDAI7lYdQUt3btMe6KcvDOwLr/keILjkurxtRZP7PWRQMT6OMOtBmkMKM6QzW/HPrRpksWEvWervcchRAwc4tX5FoA08sLW/bar/Ql3daXlvAY5sx0MXvEEzadU2DmPTVtd8iNf7EIdAWxjDljI5stOC++IAO1jIr6BIzn9PWl5Ih+xusPbyTTDoEnfhcS4iaVoxDubYwfODx55YBZZqRneDLJ8mkaovgx4978szBw9s60VDur8wIZn/YjAzQlaa0aaJ6Xbv2Qv4JnJFrF2bDIYwlndNBHxzqevwm2CP7xCGjwAzBKtf38WMWgAWSTMZ1G1UNVk5dVFFIgRQMFgAERm18SEn79Jqn6XS1ls+vLDZOOuiWvOc7hyU3DuPyXiHNX6NOP5e6AN4luMZCJwbNSiuPksbxLV5v9J5BJ+E7F8pF2Ukmrh6XtML/3AxXUziFFVFFXmxuHicmV6dGIlCmMN18HJnWcM7i7BvmWbQsRgUCmemnJWVRZVQeBvdbk8spiiRxBLRq94ayHcsfGmJgQuKyU4OTzXrgdQQOIgF/Viw3sMSrrg76KK/YjYQH/PnJBT8LtWMFIbPOjtiE09Q6r44c8M4f4YjzjPSOz5IAfuQWFTdjwILLJ9vA1Ku64AClOkFUk13f5PanjT2FCqKnbPp2ejRWyFAgjWpqZ1mC2tg9VQXtioqmaMdaHfujJl2VUKVHE55gbez77aYubtC46dd02vncNdHRREmG+2pZU2Epmtc++4ITbrzqs/y10zpa4sadXaga4r8ujqsE8FgpWkLFlYs4c0/4v5pdlbRQY0PcD59QpOCHatPC4S+92HwVE/CEvBW+pMxNpridkYqxHlqd3w5R5DymXR6JM5/N+9Qpn3oVfniFkQtqEXHp7y7uaVndkumJrz2GIL7j/9IsYPc+B+t687DbCmXf3uG3Iy17mMlvpC8QyNqfpZzVYcJW+gdclp7WFzsDF45g1rAv/+jEUCDYR4nEYYg=="s;
		static auto sign_6_384 = "KAiLtshR3cbrjUvMGNoaMXP78N3Gp8rZvHtwhd0nhvJw+o8cctZBa+fMKcmU47FaXU3xshSW3tpoTWL2pgQb75r8J7RAoF121mj0+QztbL78pVe+q/TGUFJIVCqlJpcAU8foJ+E7bYLxhpKuQSrX7ldMrE08EWbnP4W1VlRgvNFsU681LC5Kr+gPgbbsWibeDEKrePBFVkpgITR4P9mxk440hEVq9p4Q8H6OFvHGoDmihMOXQVg+O5b/+9pJD5DjAOOKChvZvipKtbzWSMOSVZCVCcLZtnHIJtmZKObi14QrkBewqjiIN+DBQS9/M83O3A8kmsYZh1wEvc97aCR2R9684mCvEHqpUVpQlIv0qLunxQx3bgVM92xvCsMFaGd7jeZSgkgrN/4+eexhT96BxeYyPqrmsaJ4e8byBICd3Vpg8hn1KFwFZ7y2+4gF0Q9wsX/ZVK45SpMwFpsqluCwIdnjM+ejmynAMZjOKbjUmJCebQyrwx6APy4QNdGm0DMVfRx+Dk4kC5v4+cjlPY/Zl1m+acw1fUctQQqCptQ9jw1tfY6ILck8a9AjuPX8lcNhVOdVHRMKuSYyIUBwn6wtTC7odMxao8Ubb1lSMPhUGuC5SVqD6oncrQchMX+JJ4dtNzA5f76+UswyBN82JeD9EomvujwkTnq9egEN1g7wKoGhNarFso6tOd2E6qV5dVOXasMs85IYub6DDlQS11bRynbdZaxzMdYTDdfk0x0x/7ewEqFYi5QrwquLfzg56A9P6SOjyaicrPWtdGoLzWvaf4ISfBH7Zwlc5tnlvaTkNj0SrJJibwohejO5KI/J6ZVibOubt2bjGN6uCIRJeig1qyFmBo5Eu4CIuWLmebTqCCxZ6RnfA8hQ0GT+DvZu1hUMuSkxtrDImM9fanLHq2BkzmemGpjBgxmvTQsM1U8smozbnyjd6X6J6RWj+sPrHiJyxqSdQp66TJ7RasHmMknAJaJ1jQeXs5lIid3+xtqdnyJwN1aPi5WVFil5HSL2BlKvozpOulUrFm2fwL26Q5I8dYDMkwY9jqLnwS549Gqe1xkIjC4AalgNkVW+DfjWFGfcc44uHSYQQ7DWD9nZ4kfyi3ozzhJ056gg+9glH7isedD8Lq+wvlpTIBdVjmf2ZpM3GLG9231OiRZDup8UEaV6MsAnXYoMmSmvWevwxfnPRXCJa87Ewwmy3tE1we0hKOVVbLqVGqMEVWRiFQJdrajWvvu0MvL3DbqqzuHnkd0dN7RN9zlLQSCJwFGzQKItejseSoAGkesbsmhDAz6yXM1GUi8ZeOFuUtpYy+G3MYGQ0iMRCcQHlNW94InnwIGyoSltEpz2PjWi1XOqa7sgkM6qzA=="s;
		static auto sign_6_512 = "Pjbv5BMUYigpXCoOWRYPsAH6sJYxZV0i7mU8vh5N8cAe4BFYFU8Euk1E+hoJlpkyKStthV7DPMfUZrT0Fz90y4TqCbTA5Wtmi8WNbzWdUoczHKTmrBHS1lEJI6FIsJNGi6OXXVKajJgGUiFNqdCGZIMcw5HdiV178b+g4W4hs3tsBFCE7PMcAsK2S6nmUcfXtLg4F9oFgtqFUvv9FqrdSGq8A3v9VjImjHkknntJRLy83NSw71oppvuXgZ3Na/BNIBxG8CtV3pwmuT4AmlBiceKQt4FUXlOb3pk58NnCb+KkiCxzQ5gu1rmHGYEAu8zo6+gilsAOHi/u5yaqVzen6Y3CqHCmjCZXOdFAuwSkOLEJvXGHtoIWtQAkF0HQYj97amLTBwojZjjLmVasI3weYKTvh7glYtRYw1vOCjqxgVnLgB/L2HIvTrPccZDj+9PC04WSk17IjH8YCa724jYR4pqTOeW0uKWORgDszznJ/DT3Kp08yuRLm37I3l9TQ5vgxZ3Y+Pe0t6sMJKv/Xvq+b/GDnYn+44sUQ/giN+HvybeSPrBFWbndWbUTyMGK4Mx8BCjRmS6m1lAciJHriSoIk08vYOPOlugrYaQBLI7NtVlJNz6jQ4h/aa5vvwKdjuk912fWSwGsxzmmc0GlbdkELxPcmw0UmRnfUkvJ9KRmCuQ5p1rgcXCpjy+Hat8cxea4q2qHFI2bs0wdMflRHxQ2JKMw5xNO+IqBt5KHGRyXiTnzwau5dluvQWeFSJdC7H0o8IMK69jq9n8ehOzRSk7SfRdBMMtJfrPb/YvRdwKmPFObM9H6NTFHZiUCX2yTr+XXVeY8xQygmO0G7i5VB0d5Ctvz2dvxU6+8aGyrNTCA0QL180LeDEcpfQrE/BuZiACOjxWDywW/ZC8Hd6uGdMmHSm4OZsoesbizp7W6IXNLxn8Qlz2YkvVm1qd7NRpIXnaFWn2bbNRatn+yEW4J3Q0waGaQr4ei9XcKGbD6sQw68lGD9n3niWHxmoEp3hdrC+1v8vEq2O1UYHp+EMPfbzL+9ceBNKRaLVoT96IfLEgUNUHLOI+P6jv7UyVKabwRV6v061Uion2B/6xlDTYUAPF/0wc9rKTz+CfBhPpdnakVPmi16bF9jkHZdA68BzczlfJsXa1Bn09ydjKU7XJJpJgoBqFDM4Jvv6n5sDTtrvSjoDAnro7yKWK9s/LWetXNl1UAqDEjnf9oO9oFie2NuXd94MSyuGz33S1kiqNiTHQWBXX1cVC785FlnUJC+rg8vmzF94ED6EOI+8KIArlHXSsK1HvaSTHvFY2OovQR+uxxYc1JwZ2iPKysNR6a9/qS13LtWSnFPbAJxwFmorlOGxMskQ=="s;


		static auto modulus_7 = "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"s;
		static auto exponent_7 = "AQAB"s;

		static auto data_7 = "jhfiueyrcinwynr98wynrilyi7oryanviynhriwucr98wp8auyiryvpw8aurnv98wyrnpiwayrcn9pyanv9pawur8pvyuap98rynv9pewytv8aytv94yvt98py89\n"s;
		static auto sign_7_1 = "ZHq+iz36QNx4g2TV1kfTQHBl/JtBC8z7ZB759rq9xfJGlRuAzEf9sAMrzoHbvbiPid6JanvufL2Hi7TROmxi3/GzqdC99BjcgAwEa7FT6gb7B7EytnlhwE4jj1WZLCAz9rSczSeEg5yjOgOFNzRAnNCk4q3j3k4s9JMHEBKxl/DtXIztKoJk4Jj9+Uum/qdRK1kbsbDpnrhxWjUPRSu3h72FdpBJAQhDThHV2S5VgTh9mScTMkkEmHIuIXF4P6J3vD+frqxLnKCi8AaRMMsBiCasQbkYU61Dk4cJwxtdwOhdAdE9wzGNBmNN+B/r1xOvLxW/7s/jNMlH5DHw794oj9Bcq2vbPEXtubAFuGOutx2iDnj25JgcIt0lIspn3gUJqu6p7mV6jXcPfO8vX+ZLsshESXsKnJ/PaZbskHyIUQp4JXla3hpZLd04CgG8c52+m9fTysgMeuJSUXgjcqpTucsGW+UIcDXrraa+npmOtnK9C6Mehi2uH0gVdOQqUpFd4FxrXyAtVAJibyyIV2GPjoYbP5kMI8BMXHn45n10Ep5eoV1+FUNiiOaxTseLO0R+7JInGurqVFUDEB/hztNBI9q8miqb9VGcm3C154Cqs3coDTVkx5ZQTAIDEc3A0D/mA6H/rRUZhtDCgxJhA1lQsMj4JJzJwevanN+NT+zzCwL8GrXYFQCeU2pQozB9WVE0QEhJpbS3IBFZFgxuKND39Fx3EliFbQCj57ndKz+VU7kZ2FsZWKNnkLevWJk/YOI/uz7lH/99c6ytiLvlwpB/dXhz9MC+ECOdf7g24D3nE1g8vNmOGJBSeaRaRwIPCPo2+mxs35VXLm/+cjsGxj0LR8CjL+Zv9V32ItN4M6aCqmsP8/m3JKBOLCG69/gmPXUGyPpnBU3P6X1m3fBXXXg0HlhYgcaE43TBY3B/RA1WCQulXPqwRw5cX7okm9SEfJDo4JHVhXfQA+MirLK8Ot3/7yhTwMnj3mJnyreeIgTqM7SLjdLwMdiCWl6ZjgUw3tah1FwCe7ylV+StVzkTfP53WzKJbK2uW6pYH0KDBwUuIs6afqctKTQvhW4PpcurPgcsuy7mcwEHGDejIsK3g31fN6TmRJoohGqEiDQGBMoOvEsWwZ6sdL+Lu7ghfyt53q/sXDBn1yJWxqMPFtTl9JoRbq0yZPcj6wT5I7ieUxNDBQyZxXX2/kD1jqmhNeRxySLmkvxltew3OTjqtekG2r/Tjowku75vxBcgYiVXjuenjm0xebK7gb5pyK2hF96yOwsjlg0wKm6UYkToRbtyy1no/eZO3AEXR9UaI4M7koGUdX97oEzxRF9Ys/91oBPsEECJYKFvrdsbxMr1ze23OKiB3/qM0H8dafswBoyCv3xV9Ynq7T0Ud5tqoHUusEgRqj/WFQ10JRhXHZKRAjBaftEB77Bv7DbIpDk0R3yPNYowFp/54RyzkVJ9o9IZRS0A6TNVdsFc9JtDMXnmxS1esLfISJ2Cr/PNmgsmu3HtUj1L2ZpBGMWTjdGktT4sHUYazcgN/oX51iqqZHmEEgEDhOrQdstHzplSWQDU1CkESWb3AZYBkYR04kpHUolF69Dj/e48YstFzyBZnoliyJhI00NegXr/tEa2JOI1VCHVBde2OxoreS3fKhe4h+u0YP278Q34Sk+6kt9ROWCcgbBjua+56uSsUoHP9vYZ7Bo52QhwL3U5OxiBvYhHjDL/uGHJwjIv7Fo5DFaYatLFlPilTV80XZMCEK2eAbRZKyCndEr7MQN1zPxBKTgvekzM8uS8gwLP3on323QTX/5C1sV/4pP0GKDSbSBLnpTbNpOFImXpwC1byB3Dri9T2wco4Ll650jZYYkCQSypLS82Ao4gWl67DIQE1zosXBhs9PtVFPAoqJt2tVjIS04Dv/jIyADU1w1lupKGvd7b9I3zX5GTYPIBAdG7rIpLM8VPFyqWapks1Noq6lSgQuLbGu2yJXW6qrKufuZEx4Qzvr8KDY9BAmfjnfqP3KmbkDAa6hsAR0XtZkmurDKMC5XEvf62rq+6yiveLcjHkGTDiHRWTuesf7EboMcsl+sJmznQKWQCKqijkH7raVkbOlvvbphOFDZBTm8M9hHkI7WgDQ4bFVngVoXjtId36Cjavw6ZQS/f67gT72DnF3s8gJ5wjcXJaJfk8RJFthHCeRz3sdNGM2eDctJK76krsIkA1WG3BjFKVMSECrOT2hpzjMho2wRA5DMQUto7WDtcVZWsOWPlWuiBRSMFxHIwkc/TL415+6n5pmb7UXTYTniIYTI5/sAV/Q30cUw7T/yA6mIhU0rhw/vuIRzNF5uvOd7/U12Mvs/YkJnAXEj56d91Dj6pipYqZFRD+9OD2gBStK8iwRGH1AUuwDElou4fdSPrCDw9GBEZ6dD06HfmAKU1EzvtqZUp0T8s0ORxiQ2SVEvqTN7GFNXQ3qMJcv1f6vGLsraux9j1NTRzFnQSCCibxgD1fQwsa/bgVKM4M34B2j2EmeCRnlBKwbFmb10jsYh13pb3jjDDTjZm4zfnQZBHn96ef6TEPhYoWxpB"s;
		static auto sign_7_256 = "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"s;
		static auto sign_7_384 = "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"s;
		static auto sign_7_512 = "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"s;

	}

	TEST(RSAKeyTests, RSATestsCreate1)
	{
		auto modulus = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::modulus_1);
		auto exponent = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::exponent_1);

		ASSERT_TRUE(modulus);
		ASSERT_TRUE(exponent);

		auto key = RSAKey::create(*modulus, *exponent);

		if (!key)
		{
			crypto::OpenSSLErros::printAllErrors(std::cerr);
		}

		ASSERT_TRUE(key);

		auto data = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::data_1);
		auto sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_1);

		ASSERT_TRUE(data);
		ASSERT_TRUE(sign);

		auto success = key->verify(*data, *sign);

		ASSERT_TRUE(success);
		EXPECT_TRUE(*success);
	}

	TEST(RSAKeyTests, RSAKeyTestsCreate2)
	{
		auto modulus = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::modulus_2);
		auto exponent = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::exponent_2);

		ASSERT_TRUE(modulus);
		ASSERT_TRUE(exponent);

		auto key = RSAKey::create(*modulus, *exponent);

		if (!key)
		{
			crypto::OpenSSLErros::printAllErrors(std::cerr);
		}

		ASSERT_TRUE(key);
	}

	TEST(RSAKeyTests, RSAKey2048_PKCS1_v1_5)
	{
		auto modulus = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::modulus_3);
		auto exponent = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::exponent_3);

		ASSERT_TRUE(modulus);
		ASSERT_TRUE(exponent);

		auto key = RSAKey::create(*modulus, *exponent);

		if (!key)
		{
			crypto::OpenSSLErros::printAllErrors(std::cerr);
		}

		ASSERT_TRUE(key);

		std::vector<std::byte> data{};
		std::ranges::transform(helpers::data_3, std::back_inserter(data), [](auto x) { return static_cast<std::byte>(x); });

		auto sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_3_1);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA1);
		auto result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);

		sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_3_256);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA256);
		result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);

		sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_3_384);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA384);
		result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);

		sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_3_512);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA512);
		result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);
	}

	TEST(RSAKeyTests, RSAKey3072_PKCS1_v1_5)
	{
		auto modulus = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::modulus_4);
		auto exponent = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::exponent_4);

		ASSERT_TRUE(modulus);
		ASSERT_TRUE(exponent);

		auto key = RSAKey::create(*modulus, *exponent);

		if (!key)
		{
			crypto::OpenSSLErros::printAllErrors(std::cerr);
		}

		ASSERT_TRUE(key);

		std::vector<std::byte> data{};
		std::ranges::transform(helpers::data_4, std::back_inserter(data), [](auto x) { return static_cast<std::byte>(x); });

		auto sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_4_1);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA1);
		auto result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);

		sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_4_256);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA256);
		result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);

		sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_4_384);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA384);
		result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);

		sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_4_512);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA512);
		result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);
	}

	TEST(RSAKeyTests, RSAKey4096_PKCS1_v1_5)
	{
		auto modulus = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::modulus_5);
		auto exponent = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::exponent_5);

		ASSERT_TRUE(modulus);
		ASSERT_TRUE(exponent);

		auto key = RSAKey::create(*modulus, *exponent);

		if (!key)
		{
			crypto::OpenSSLErros::printAllErrors(std::cerr);
		}

		ASSERT_TRUE(key);

		std::vector<std::byte> data{};
		std::ranges::transform(helpers::data_5, std::back_inserter(data), [](auto x) { return static_cast<std::byte>(x); });

		auto sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_5_1);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA1);
		auto result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);

		sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_5_256);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA256);
		result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);

		sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_5_384);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA384);
		result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);

		sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_5_512);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA512);
		result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);
	}

	TEST(RSAKeyTests, RSAKey8192_PKCS1_v1_5)
	{
		auto modulus = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::modulus_6);
		auto exponent = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::exponent_6);

		ASSERT_TRUE(modulus);
		ASSERT_TRUE(exponent);

		auto key = RSAKey::create(*modulus, *exponent);

		if (!key)
		{
			crypto::OpenSSLErros::printAllErrors(std::cerr);
		}

		ASSERT_TRUE(key);

		std::vector<std::byte> data{};
		std::ranges::transform(helpers::data_6, std::back_inserter(data), [](auto x) { return static_cast<std::byte>(x); });

		auto sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_6_1);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA1);
		auto result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);

		sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_6_256);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA256);
		result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);

		sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_6_384);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA384);
		result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);

		sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_6_512);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA512);
		result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);
	}

	TEST(RSAKeyTests, RSAKey15360_PKCS1_v1_5)
	{
		auto modulus = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::modulus_7);
		auto exponent = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::exponent_7);

		ASSERT_TRUE(modulus);
		ASSERT_TRUE(exponent);

		auto key = RSAKey::create(*modulus, *exponent);

		if (!key)
		{
			crypto::OpenSSLErros::printAllErrors(std::cerr);
		}

		ASSERT_TRUE(key);

		std::vector<std::byte> data{};
		std::ranges::transform(helpers::data_7, std::back_inserter(data), [](auto x) { return static_cast<std::byte>(x); });

		auto sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_7_1);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA1);
		auto result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);

		sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_7_256);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA256);
		result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);

		sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_7_384);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA384);
		result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);

		sign = crypto::base64::fromBase64Fix<std::vector<std::byte>>(helpers::sign_7_512);
		ASSERT_TRUE(sign);
		key->setDefaultHash(COSE::SIGNATURE_HASH::SHA512);
		result = key->verify(data, *sign);
		ASSERT_TRUE(result);
		EXPECT_TRUE(*result);
	}
}