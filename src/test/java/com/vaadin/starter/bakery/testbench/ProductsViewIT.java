package com.vaadin.starter.bakery.testbench;

import java.util.Random;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.support.ui.ExpectedCondition;

import com.vaadin.flow.component.grid.testbench.GridElement;
import com.vaadin.flow.component.grid.testbench.GridTHTDElement;
import com.vaadin.flow.component.textfield.testbench.TextFieldElement;
import com.vaadin.starter.bakery.testbench.elements.ui.ProductsViewElement;
import com.vaadin.starter.bakery.testbench.elements.ui.StorefrontViewElement;
import com.vaadin.testbench.BrowserTest;

public class ProductsViewIT extends AbstractIT<ProductsViewElement> {

	private static Random r = new Random();

	@Override
	protected ProductsViewElement openView() {
		StorefrontViewElement storefront = openLoginView().login("admin@vaadin.com", "admin");
		return storefront.getMenu().navigateToProducts();
	}

	@BrowserTest
	public void editProductTwice() {
		ProductsViewElement productsPage = openView();

		String uniqueName = "Unique cake name " + r.nextInt();
		String initialPrice = "98.76";
		int rowNum = createProduct(productsPage, uniqueName, initialPrice);
		productsPage.openRowForEditing(rowNum);

		Assertions.assertTrue(productsPage.getCrud().isEditorOpen());
		String newValue = "New " + uniqueName;
		TextFieldElement nameField = productsPage.getProductName();
		nameField.setValue(newValue);

		productsPage.getCrud().getEditorSaveButton().click();
		Assertions.assertFalse(productsPage.getCrud().isEditorOpen());
		GridElement grid = productsPage.getCrud().getGrid();
		Assertions.assertEquals(rowNum, grid.getCell(newValue).getRow());

		productsPage.openRowForEditing(rowNum);
		newValue = "The " + newValue;
		nameField = productsPage.getProductName();
		nameField.setValue(newValue);

		productsPage.getCrud().getEditorSaveButton().click();
		Assertions.assertFalse(productsPage.getCrud().isEditorOpen());
		Assertions.assertEquals(rowNum, grid.getCell(newValue).getRow());
	}

	@BrowserTest
	public void editProduct() {
		ProductsViewElement productsPage = openView();

		String url = getDriver().getCurrentUrl();

		String uniqueName = "Unique cake name " + r.nextInt();
		String initialPrice = "98.76";
		int rowIndex = createProduct(productsPage, uniqueName, initialPrice);

		productsPage.openRowForEditing(rowIndex);
		Assertions.assertTrue(getDriver().getCurrentUrl().length() > url.length());

		Assertions.assertTrue(productsPage.getCrud().isEditorOpen());

		TextFieldElement price = productsPage.getPrice();
		Assertions.assertEquals(initialPrice, price.getValue());

		price.setValue("123.45");

		productsPage.getCrud().getEditorSaveButton().click();

		Assertions.assertFalse(productsPage.getCrud().isEditorOpen());

		Assertions.assertTrue(getDriver().getCurrentUrl().endsWith("products"));

		productsPage.openRowForEditing(rowIndex);

		price = productsPage.getPrice(); // Requery the price element.
		Assertions.assertEquals("123.45", price.getValue());

		// Return initial value
		price.setValue(initialPrice);

		productsPage.getCrud().getEditorSaveButton().click();
		Assertions.assertFalse(productsPage.getCrud().isEditorOpen());
	}

	@BrowserTest
	public void testCancelConfirmationMessage() {
		ProductsViewElement productsPage = openView();

		productsPage.getCrud().getNewItemButton().get().click();
		Assertions.assertTrue(productsPage.getCrud().isEditorOpen());
		productsPage.getProductName().setValue("Some name");
		productsPage.getCrud().getEditorCancelButton().click();
		Assertions.assertEquals(productsPage.getDiscardConfirmDialog().getHeaderText(), "Discard changes");
	}

	private int createProduct(ProductsViewElement productsPage, String name, String price) {
		productsPage.getSearchBar().getCreateNewButton().click();

		Assertions.assertTrue(productsPage.getCrud().isEditorOpen());

		TextFieldElement nameField = productsPage.getProductName();
		TextFieldElement priceField = productsPage.getPrice();

		nameField.setValue(name);
		priceField.setValue(price);

		productsPage.getCrud().getEditorSaveButton().click();
		Assertions.assertFalse(productsPage.getCrud().isEditorOpen());

		return waitUntil((ExpectedCondition<GridTHTDElement>) wd -> productsPage.getCrud().getGrid().getCell(name)).getRow();
	}

}
