v2.11.0 / 2021-07-14
========================


v2.11.0-RC2 / 2021-07-12
========================


v2.11.0-RC1 / 2021-07-07
========================


v2.10.0 / 2021-06-14
========================


v2.10.0-RC2 / 2021-06-11
========================


v2.10.0-RC1 / 2021-06-08
========================


v2.9.0 / 2021-05-13
========================


v2.9.0-RC2 / 2021-05-10
========================


v2.9.0-RC1 / 2021-05-06
========================


v2.8.0 / 2021-04-14
========================


v2.8.0-RC2 / 2021-04-12
========================


v2.8.0-RC1 / 2021-04-07
========================


v2.7.0 / 2021-03-11
========================
* Fix zc_nvlist_dst buffer allocation when ioctl is ZFS_IOC_ERROR_LOG. ([#82](https://github.com/openebs/libcstor/pull/82),[@sgielen](https://github.com/sgielen))


v2.7.0-RC2 / 2021-03-10
========================


v2.7.0-RC1 / 2021-03-08
========================
* Fix zc_nvlist_dst buffer allocation when ioctl is ZFS_IOC_ERROR_LOG. ([#82](https://github.com/openebs/libcstor/pull/82),[@sgielen](https://github.com/sgielen))


v2.6.0 / 2021-02-13
========================


v2.6.0-RC2 / 2021-02-11
========================


v2.6.0-RC1 / 2021-02-08
========================


v2.5.0 / 2021-01-13
========================


v2.5.0-RC2 / 2021-01-11
========================


v2.5.0-RC1 / 2021-01-08
========================


v2.4.0 / 2020-12-13
========================


v2.4.0-RC2 / 2020-12-12
========================


v2.4.0-RC1 / 2020-12-10
========================


v2.3.0 / 2020-11-14
========================
* chore(build): add support for multiarch build  ([#71](https://github.com/openebs/libcstor/pull/71),[@shubham14bajpai](https://github.com/shubham14bajpai))
* fix(travis): add suffix to single arch image pushed by travis ([#78](https://github.com/openebs/libcstor/pull/78),[@shubham14bajpai](https://github.com/shubham14bajpai))


v2.3.0-RC2 / 2020-11-13
========================


v2.3.0-RC1 / 2020-11-12
========================
* chore(build): add support for multiarch build  ([#71](https://github.com/openebs/libcstor/pull/71),[@shubham14bajpai](https://github.com/shubham14bajpai))
* fix(travis): add suffix to single arch image pushed by travis ([#78](https://github.com/openebs/libcstor/pull/78),[@shubham14bajpai](https://github.com/shubham14bajpai))


v2.2.0 / 2020-10-13
========================


v2.1.0 / 2020-09-14
========================
* chore(build): build and push images to repositories from libcstor ([#70](https://github.com/openebs/libcstor/pull/70),[@mittachaitu](https://github.com/mittachaitu))
* feat(build): Add RTE header files for ppc builds ([#69](https://github.com/openebs/libcstor/pull/69),[@shubham14bajpai](https://github.com/shubham14bajpai))


v2.0.0 / 2020-08-14
========================


v1.12.0 / 2020-07-13
========================


v1.11.0 / 2020-06-13
========================


1.10.0 / 2020-05-14
========================


1.9.0 / 2020-04-14
========================
* added new command listsnap under zfs to list the snapshots for dataset from cache ([#49](https://github.com/openebs/libcstor/pull/49),[@vishnuitta](https://github.com/vishnuitta))


1.9.0-RC1 / 2020-04-07
========================
* added new command listsnap under zfs to list the snapshots for dataset from cache ([#49](https://github.com/openebs/libcstor/pull/49),[@vishnuitta](https://github.com/vishnuitta))


1.8.0 / 2020-03-13
========================
* added readonly support for uzfs pool ([#43](https://github.com/openebs/libcstor/pull/43),[@mynktl](https://github.com/mynktl))
* added support of fetching specific snapshot details through istgt/target ([#46](https://github.com/openebs/libcstor/pull/46),[@mynktl](https://github.com/mynktl))


1.8.0-RC1 / 2020-03-06
========================
* added readonly support for uzfs pool ([#43](https://github.com/openebs/libcstor/pull/43),[@mynktl](https://github.com/mynktl))
* added support of fetching specific snapshot details through istgt/target ([#46](https://github.com/openebs/libcstor/pull/46),[@mynktl](https://github.com/mynktl))


1.7.0-RC1 / 2020-02-07
========================
* updated sock file(uzfs.sock) directory to /var/tmp/sock from /tmp/ ([#44](https://github.com/openebs/libcstor/pull/44),[@mittachaitu](https://github.com/mittachaitu))
* added support of making uzfs zvol readonly ([#41](https://github.com/openebs/libcstor/pull/41),[@mynktl](https://github.com/mynktl))
* fixed inflight io count calculation ([#39](https://github.com/openebs/libcstor/pull/39),[@mittachaitu](https://github.com/mittachaitu))
