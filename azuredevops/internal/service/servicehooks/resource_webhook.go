package servicehooks

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/customdiff"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/microsoft/azure-devops-go-api/azuredevops/servicehooks"
	"github.com/microsoft/terraform-provider-azuredevops/azuredevops/internal/client"
	"github.com/microsoft/terraform-provider-azuredevops/azuredevops/internal/utils"
	"github.com/microsoft/terraform-provider-azuredevops/azuredevops/internal/utils/converter"
	"github.com/microsoft/terraform-provider-azuredevops/azuredevops/internal/utils/tfhelper"
)

func ResourceWebhook() *schema.Resource {
	return &schema.Resource{
		Create:   resourceWebhookCreate,
		Read:     resourceWebhookRead,
		Update:   resourceWebhookUpdate,
		Delete:   resourceWebhookDelete,
		Importer: tfhelper.ImportProjectQualifiedResourceUUID(),
		Schema: map[string]*schema.Schema{
			"project_id": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.IsUUID,
			},
			"url": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.IsURLWithHTTPS,
			},
			"event_type": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringIsNotWhiteSpace,
			},
			"basic_auth_username": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringIsNotWhiteSpace,
			},
			"basic_auth_password": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringIsNotWhiteSpace,
			},
			// "basic_auth": {
			// 	Type:         schema.TypeSet,
			// 	Optional:     true,
			// 	Elem: &schema.Resource{
			// 		Schema: map[string]*schema.Schema{
			// 			"username": {
			// 				Type:     schema.TypeString,
			// 				Optional: true,
			// 			},
			// 			"password": {
			// 				Type:     schema.TypeString,
			// 				Optional: true,
			// 			},
			// 		},
			// 	},
			// 	MaxItems: 1,
			// },
			"updated_at": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"http_headers": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"filters": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
		CustomizeDiff: customdiff.All(
			customdiff.ForceNewIf("basic_auth_password", func(d *schema.ResourceDiff, meta interface{}) bool {
				return d.HasChange("updated_at")
			}),
		),
	}
}

func resourceWebhookCreate(d *schema.ResourceData, m interface{}) error {
	clients := m.(*client.AggregatedClient)

	subscriptionData := getSubscription(d)

	subscription, err := clients.ServiceHooksClient.CreateSubscription(clients.Ctx, servicehooks.CreateSubscriptionArgs{
		Subscription: &subscriptionData,
	})

	if err != nil {
		return err
	}

	d.SetId(subscription.Id.String())

	return resourceWebhookRead(d, m)
}

func resourceWebhookRead(d *schema.ResourceData, m interface{}) error {
	clients := m.(*client.AggregatedClient)

	subscriptionId := d.Id()

	subscription, err := clients.ServiceHooksClient.GetSubscription(clients.Ctx, servicehooks.GetSubscriptionArgs{
		SubscriptionId: converter.UUID(subscriptionId),
	})

	if err != nil {
		if utils.ResponseWasNotFound(err) {
			d.SetId("")
			return nil
		}
		return err
	}

	d.Set("project_id", (*subscription.PublisherInputs)["projectId"])
	d.Set("url", (*subscription.ConsumerInputs)["url"])
	d.Set("event_type", *subscription.EventType)

	basicAuth := map[string]string{}
	if username, ok := (*subscription.ConsumerInputs)["basicAuthUsername"]; ok {
		basicAuth["username"] = username
		d.Set("basic_auth_username", username)
	}
	// if password, ok := (*subscription.ConsumerInputs)["basicAuthPassword"]; ok {
	// 	basicAuth["password"] = password
	// 	// d.Set("basic_auth_password_hash", d.Get("basic_auth_password").(string))
	// 	d.Set("basic_auth_password", password)
	// }
	// if password := d.Get("basic_auth").(map[string]interface{})["password"].(string); password != "" {
	// basicAuth["password"] = password
	// d.Set("basic_auth_password", password)
	// }
	// d.Set("basic_auth", basicAuth)
	d.Set("updated_at", subscription.ModifiedDate.String())
	// if d.HasChange("updated_at") {
	// 	d.Set("basic_auth_password", "********")
	// }

	// http headers are returned as string -> we need to parse them
	httpHeadersString := (*subscription.ConsumerInputs)["httpHeaders"]
	reader := bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\n" + (*subscription.ConsumerInputs)["httpHeaders"] + "\r\n\n"))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return errors.New(fmt.Sprintf("could not parse subscription http headers: %s", httpHeadersString))
	}

	httpHeaders := map[string]string{}
	for header, values := range req.Header {
		httpHeaders[header] = strings.Join(values, ", ")
	}
	d.Set("http_headers", httpHeaders)

	filters := map[string]string{}
	for key, value := range *subscription.PublisherInputs {
		if key == "projectId" || key == "tfsSubscriptionId" {
			continue
		}
		filters[key] = value
	}
	d.Set("filters", filters)

	return nil
}

func resourceWebhookUpdate(d *schema.ResourceData, m interface{}) error {
	clients := m.(*client.AggregatedClient)

	subscriptionData := getSubscription(d)

	if _, err := clients.ServiceHooksClient.ReplaceSubscription(clients.Ctx, servicehooks.ReplaceSubscriptionArgs{
		SubscriptionId: converter.UUID(d.Id()),
		Subscription:   &subscriptionData,
	}); err != nil {
		return err
	}

	return resourceWebhookRead(d, m)
}

func resourceWebhookDelete(d *schema.ResourceData, m interface{}) error {
	clients := m.(*client.AggregatedClient)

	err := clients.ServiceHooksClient.DeleteSubscription(clients.Ctx, servicehooks.DeleteSubscriptionArgs{
		SubscriptionId: converter.UUID(d.Id()),
	})

	if err != nil {
		return err
	}

	d.SetId("")
	return nil
}

func getSubscription(d *schema.ResourceData) servicehooks.Subscription {
	publisherId := "tfs"
	eventType := d.Get("event_type").(string)
	url := d.Get("url").(string)
	consumerId := "webHooks"
	consumerActionId := "httpRequest"
	// basicAuth := d.Get("basic_auth").(map[string]interface{})
	httpHeaders := d.Get("http_headers").(map[string]interface{})
	filters := d.Get("filters").(map[string]interface{})

	consumerInputs := map[string]string{
		"url": url,
	}
	// if username, ok := basicAuth["username"]; ok {
	// 	consumerInputs["basicAuthUsername"] = username.(string)
	// }
	// if password, ok := basicAuth["password"]; ok {
	// 	consumerInputs["basicAuthPassword"] = password.(string)
	// }
	if username := d.Get("basic_auth_username").(string); username != "" {
		consumerInputs["basicAuthUsername"] = username
	}
	if password := d.Get("basic_auth_password").(string); password != "" {
		consumerInputs["basicAuthPassword"] = password
	}

	httpHeadersSlice := []string{}
	for header, value := range httpHeaders {
		httpHeadersSlice = append(httpHeadersSlice, fmt.Sprintf("%s: %s", header, value.(string)))
	}
	httpHeadersStr := strings.Join(httpHeadersSlice, "\n")
	if httpHeadersStr != "" {
		consumerInputs["httpHeaders"] = httpHeadersStr
	}

	publisherInputs := map[string]string{}
	for key, value := range filters {
		publisherInputs[key] = value.(string)
	}
	publisherInputs["projectId"] = d.Get("project_id").(string)

	subscriptionData := servicehooks.Subscription{
		PublisherId:      &publisherId,
		EventType:        &eventType,
		ConsumerId:       &consumerId,
		ConsumerActionId: &consumerActionId,
		PublisherInputs:  &publisherInputs,
		ConsumerInputs:   &consumerInputs,
	}

	return subscriptionData
}

func validateBasicAuth(i interface{}, k string) ([]string, []error) {
	var errors []error
	var warnings []string

	m := i.(map[string]interface{})

	if len(m) <= 0 {
		errors = append(errors, fmt.Errorf("Feature map must contain at least on entry"))
	}

	for key := range m {
		if key != "username" && key != "password" {
			errors = append(errors, fmt.Errorf("unknown key in basic_auth map: %s", key))
		}
	}

	return warnings, errors
}
