package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

type DNSUpdater interface {
	// Upsert sets the A/AAAA record of every fqdn to ip, all inside one hosted zone.
	Upsert(ctx context.Context, zoneID, recordType, ip string, records []Domain) (changeID string, err error)
	FindZone(ctx context.Context, fqdn string) (string, error)
}

type route53Updater struct{ c *route53.Client }

func newRoute53(ctx context.Context, cfg AWSConfig) (*route53Updater, error) {
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(cfg.Region)}
	if cfg.AccessKeyID != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, "")))
	} // otherwise: default chain (env vars, ~/.aws, instance role)
	ac, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &route53Updater{route53.NewFromConfig(ac)}, nil
}

func (r *route53Updater) Upsert(ctx context.Context, zoneID, recordType, ip string, recs []Domain) (string, error) {
	changes := make([]r53types.Change, 0, len(recs))
	for _, d := range recs {
		changes = append(changes, r53types.Change{
			Action: r53types.ChangeActionUpsert,
			ResourceRecordSet: &r53types.ResourceRecordSet{
				Name:            aws.String(d.FQDN + "."),
				Type:            r53types.RRType(recordType),
				TTL:             aws.Int64(d.TTL),
				ResourceRecords: []r53types.ResourceRecord{{Value: aws.String(ip)}},
			},
		})
	}
	out, err := r.c.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &r53types.ChangeBatch{
			Comment: aws.String("go-ddns"),
			Changes: changes,
		},
	})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.ChangeInfo.Id), nil
}

// FindZone walks up the labels of fqdn and returns the most specific
// public hosted zone that contains it.
func (r *route53Updater) FindZone(ctx context.Context, fqdn string) (string, error) {
	labels := strings.Split(normalizeFQDN(fqdn), ".")
	for i := 0; i < len(labels)-1; i++ {
		name := strings.Join(labels[i:], ".") + "."
		out, err := r.c.ListHostedZonesByName(ctx, &route53.ListHostedZonesByNameInput{
			DNSName: aws.String(name), MaxItems: aws.Int32(5),
		})
		if err != nil {
			return "", err
		}
		for _, z := range out.HostedZones {
			if aws.ToString(z.Name) == name && (z.Config == nil || !z.Config.PrivateZone) {
				return strings.TrimPrefix(aws.ToString(z.Id), "/hostedzone/"), nil
			}
		}
	}
	return "", fmt.Errorf("no public hosted zone found for %s", fqdn)
}

// dryRunUpdater only logs; handy for testing without touching AWS.
type dryRunUpdater struct{}

func (dryRunUpdater) Upsert(_ context.Context, zoneID, rt, ip string, recs []Domain) (string, error) {
	names := make([]string, len(recs))
	for i, d := range recs {
		names[i] = d.FQDN
	}
	log.Printf("[dry-run] zone=%s UPSERT %s %s -> %s", zoneID, rt, strings.Join(names, ","), ip)
	return "dry-run", nil
}

func (dryRunUpdater) FindZone(context.Context, string) (string, error) {
	return "", fmt.Errorf("dry_run: pass -zone explicitly")
}
