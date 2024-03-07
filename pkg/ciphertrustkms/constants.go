/*
 *  Copyright (c) 2024 Thales Group Limited. All Rights Reserved.
 *  This software is the confidential and proprietary information of Thales Group.
 *  
 *  Thales Group MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF 
 *  THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 *  TO THE IMPLIED WARRANTIES OR MERCHANTABILITY, FITNESS FOR A
 *  PARTICULAR PURPOSE, OR NON-INFRINGEMENT. Thales Group SHALL NOT BE
 *  LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE AS RESULT OF USING,
 *  MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.

 *  THIS SOFTWARE IS NOT DESIGNED OR INTENDED FOR USE OR RESALE AS ON-LINE
 *  CONTROL EQUIPMENT IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE
 *  PERFORMANCE, SUCH AS IN THE OPERATION OF NUCLEAR FACILITIES, AIRCRAFT
 *  NAVIGATION OR COMMUNICATION SYSTEMS, AIR TRAFFIC CONTROL, DIRECT LIFE
 *  SUPPORT MACHINES, OR WEAPONS SYSTEMS, IN WHICH THE FAILURE OF THE
 *  SOFTWARE COULD LEAD DIRECTLY TO DEATH, PERSONAL INJURY, OR SEVERE
 *  PHYSICAL OR ENVIRONMENTAL DAMAGE ("HIGH RISK ACTIVITIES"). Thales Group
 *  SPECIFICALLY DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF FTNESS FOR
 *  HIGH RISK ACTIVITIES;
 *
 */

package ciphertrustkms

import "time"

const (
	PluginName = "ciphertrust_kms"

	AlgorithmTag             = "algorithm"
	CryptoKeyNameTag         = "crypto_key_name"
	CryptoKeyVersionNameTag  = "crypto_key_version_name"
	CryptoKeyVersionStateTag = "crypto_key_version_state"
	ScheduledDestroyTimeTag  = "scheduled_destroy_time"
	ReasonTag                = "reason"

	DisposeCryptoKeysFrequency    = time.Hour * 24
	KeepActiveCryptoKeysFrequency = time.Hour * 6
	MaxStaleDuration              = time.Hour * 24 * 14 // Two weeks

	CryptoKeyNamePrefix = "spire-key"
	LabelNameServerID   = "spire-server-id"
	LabelNameLastUpdate = "spire-last-update"
	LabelNameServerTD   = "spire-server-td"
	LabelNameActive     = "spire-active"

	GetPublicKeyMaxAttempts = 10
)
