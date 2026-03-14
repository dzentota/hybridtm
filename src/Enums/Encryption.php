<?php
declare(strict_types=1);
namespace HybridTM\Enums;

/** Encryption values as accepted by Threagile 1.x. */
enum Encryption: string {
    case None = 'none';
    case Transparent = 'transparent';
    case DataWithSymmetricSharedKey = 'data-with-symmetric-shared-key';
    case DataWithAsymmetricSharedKey = 'data-with-asymmetric-shared-key';
    case DataWithEnduserIndividualKey = 'data-with-enduser-individual-key';
}
